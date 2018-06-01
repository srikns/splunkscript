#!/usr/bin/perl
#
use warnings;
my $LOGFILE = "/opt/Introscope/scripts/JMXaudit/wily_data.log";
my $JAVA = "/opt/Introscope/jre/bin/java";
my $CLWorkstation = "/opt/Introscope/lib/CLWorkstation.jar";
my $RCUSER = "rcollector";
my $RCPASS = "rcollector";
my $WILYMOM = "yourWilyMOM";
my $WILYPORT = 5001;
my $agentRegex = $ARGV[0];
# my $agentRegex = '.*b1\.c1\..*-ba1';
my $metricRegex = 'JMX.*';
my $domainRegex = 'SuperDomain';

# Offset the query by one minute to guarantee a full minutes worth of data is available:
my $offset = 60;
# Amount/range of data to query for:
my $range = 60;
# Frequency is the duration of each interval in the range:
my $frequency = 60;
# Duration in seconds to wait before killing stale CLWCommands
my $timeout = 45;

open LOG, ">>$LOGFILE" || die "cannot open logfile $LOGFILE: $!";

use POSIX qw/strftime/;
my $startTime = time();
my $date1 = strftime("%D %R", localtime($startTime - $offset - $range * 1));
my $date2 = strftime("%D %R", localtime($startTime - $offset - $range * 0));

# Resulting CLW Command:
my $CLWCommand = "'$JAVA' -Xmx128M -Duser='$RCUSER' -Dpassword='$RCPASS' -Dhost='$WILYMOM'  -Dport='$WILYPORT' -jar '$CLWorkstation' " .
        "get historical data from agents matching '$agentRegex' and metrics matching '$metricRegex' " .
        "for past 5 minute with frequency of 60 seconds";
#        "between '$date1' and '$date2' with frequency of $frequency seconds";

# CSV Output Header
print "Domain,Host,Process,AgentName,Resource,MetricName,CorrectedValue\n";

my $sumMetricCount = 0;
my $sumValueCount = 0;

print "Running CLWorkstation query for values between $date1 and $date2\n";
print LOG localtime()." INFO: Running CLWorkstation query for values between $date1 and $date2\n";

# Execute and open pipe for the CLWCommand
my $clwpid = open (CLW, $CLWCommand . ' |') or die "Could not create pipe: $!\n";

# Kill the CLWCommand if it takes longer than $timeout seconds
local $SIG{ALRM} = sub {
        print STDERR "Timeout occured reading from pipe. CLWCommand: $CLWCommand\n";
        print LOG localtime()." ERROR: Timeout occured reading from pipe. CLWCommand: $CLWCommand\n";
        kill 9, $clwpid;
};
alarm $timeout;

# Iterate each line of output from the CLW query
while (<CLW>)
{
        # skip first two lines:
        next if 1..2;

        # Parse the line of CLW output
        my @fields = split (/,/, $_);
        # Ignore input unless its exactly 21 columns
        next unless @fields == 21;
        my ($Domain, $Host, $Process, $AgentName, $Resource, $MetricName, $RecordType, $Period,
               $IntendedEndTimestamp, $ActualStartTimestamp, $ActualEndTimestamp,
               $ValueCount, $ValueType, $IntegerValue, $IntegerMin, $IntegerMax,
               $FloatValue, $FloatMin, $FloatMax, $StringValue, $DateValue, $Extra) = @fields;

        next if $Domain !~ $domainRegex;
        next unless $ValueType eq "Integer" or $ValueType eq "Long";

        # Correct values for IntCounter and LongCounter metrics
        my $CorrectedValue = $IntegerValue;
        if (
                $IntegerValue == $IntegerMax && # sig of IntCounter: value=max, min=any, count=any
                !(
                        $IntegerMax == $ValueCount && $IntegerMin == 0 || #sig of PIC: value==max=count, min=0
                        $IntegerMax == $IntegerMin  # sig of avg: min<=value<=max, count=any
                )
        ) {
                $CorrectedValue = ($IntegerMin+$IntegerMax)/2;
        }

                $sumMetricCount++;
        $sumValueCount++ unless $ValueCount == 0;

        # Output line of CSV
        print "$Domain,$Host!$Process!$AgentName,$Resource,$MetricName,$CorrectedValue\n";
}

alarm 0;

close (CLW);
my $pipestatus = ($? >> 8);
if ($pipestatus) {
        print STDERR "Error code $pipestatus while running CLWCommand: $CLWCommand\n";
        print LOG localtime()." ERROR: Return code of $pipestatus while running CLWCommand: $CLWCommand\n";
}

print LOG localtime()." INFO: Finished in: ".(time()-$startTime)." seconds. sumMetricCount=$sumMetricCount, sumValueCount=$sumValueCount\n";
close (LOG);
