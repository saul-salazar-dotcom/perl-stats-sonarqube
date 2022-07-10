#!/usr/bin/env perl
use Data::Dumper;
use Try::Tiny;
use strict;
use warnings;
use 5.010;
use JSON -support_by_pp;
use FindBin;

# Turn off output buffering
$|=1;

# read project keys from file
my $file = "$FindBin::Bin/instances.txt";
open(my $fhi, '<:encoding(UTF-8)', $file)
  or die "Could not open file '$file' $!";

my %name_hash;
while (my $key = <$fhi>) {
    chomp $key;
    my ($p,$n) = split ("::",$key);
    $name_hash{$p}{DESC} = $n;
}
close($fhi);

die "Error: secret not defined in the Environment Variable \'m\'\nTo fix, run:\nsource ~/.bash_profile\n" if (! $ENV{'sonar_password'});

# for curl
my $who         = 'sonar_username:' . $ENV{'sonar_password'};
my $status_path = '/api/system/status';
my $engine_path = '/api/ce/activity?type=REPORT'; 
my $top_url     = 'https://sonar.tools.YOURCOMPANY.com/';
my $options     = "--insecure --silent -u $who -b cookie.txt -c cookie.txt";

# print CSV header
print "Project Key,Server Status,Version,Scans Available,Last Scan,Total Projects,Total Open Issues,Projects QualityGate not set,Projects QualityGate Error,Projects QualityGate OK,Coverage less than 50, Coverage greater than 50,Languages,Project Description\n";

# let's loop through all project keys and get the status
foreach my $key(sort keys %name_hash) {
    chomp $key;

    my $last_scan = "N/A";
    my $desc      = $name_hash{$key}{'DESC'};

    # let's get the server status first
    my $url   = $top_url . $key . $status_path;
    my $is_up = `curl -k -s -o /dev/null -I -w "%{http_code}" $url`;
    #print "curl -k -s -o /dev/null -I -w \"%{http_code}\" $url\n";
    if ($is_up ne '200') {
	    print "$key,DOWN,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,$desc\n";
	    next;
    }

    # let's get SonarQube version
    my $ver_data      = `curl -s -q -k $url 2>/dev/null`;    
    my $json_v        = JSON->new->pretty;
    my $json_object_v = $json_v->decode($ver_data);
    my $sonar_version = $json_object_v->{version};

    # lets get scan data
    # sometimes we're able to get the Server Version but the engine has issues
    # we report this as DOWN
    $url = $top_url . $key . $engine_path;
    my $data = `curl -s -q -k -u $who $url 2>/dev/null`;
    if ($data =~ /404 Not Found|Service Unavailable|502 Bad Gateway|500 Internal Server Error|ConnectionNotEstablished/ ) {
        print "$key,DOWN,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,NA,$desc\n";
        next;
    }

    # validate scan data
    if ($data eq '') {
        print "$key,UP,$sonar_version,NO,NA,NA,NA,NA,NA,NA,NA,NA,NA,$desc\n";
        next;
    }

    # did not find any scans on this server
    my $json = JSON->new->pretty;
    my $json_object = $json->decode($data);
    if (! @{$json_object->{tasks}} ) {
        print "$key,UP,$sonar_version,NO,NA,NA,NA,NA,NA,NA,NA,NA,NA,$desc\n";
        next;
    }

    # found some scans
    # let's get the timestamp of the lastest scan and print the data in CSV format
    foreach my $entry( @{$json_object->{tasks}} ){
	    $last_scan = $entry->{executedAt};
	    last;
    }

    # METRIC: Number of projects on each server
    $url = $top_url . $key . '/api/components/search?qualifiers=TRK&ps=1000';
    my $projectsResponse  = `curl $options "$url"`;
    my $projectsJson      = $json->decode($projectsResponse);
    my $projectsTotal     = int($projectsJson->{paging}->{total} || 0);
    my $openIssuesTotal   = 0;

    my $projectsWithoutQualityGate = 0;
    my $projectsQualityGateSuccess = 0;
    my $projectsQualityGateError   = 0;

    my $projectsWithCoverage50 = 0;
    my $projectsWithoutCoverage = 0;

    foreach my $project (@{$projectsJson->{components}}) {
        my $id = $project->{id};
        my $projectKey = $project->{key};

        # METRIC: How many projects passed the Quality Gate vs. how many projects failed, per instance
        $url = $top_url . $key . "/api/qualitygates/project_status?projectId=$id";
        my $qualityGateResponse = `curl $options "$url"`;
        my $qualityGateJson = $json->decode($qualityGateResponse);
        my $qualityGateStatus = $qualityGateJson->{projectStatus}->{status};

        if ($qualityGateStatus eq "NONE") {
            $projectsWithoutQualityGate++;
        } elsif ($qualityGateStatus eq "ERROR" || $qualityGateStatus eq "WARN") {
            $projectsQualityGateError++;
        } elsif ($qualityGateStatus eq "OK") {
            $projectsQualityGateSuccess++;
        }

        # METRIC: How many projects meet the code coverage % vs how many don’t
        $url = $top_url . $key . "/api/measures/component?metricKeys=coverage&componentId=$id";
        my $coverageResponse = `curl $options "$url"`;
        $coverageResponse = $json->decode($coverageResponse);
        my $measures = $coverageResponse->{component}->{measures};
        my $measuresAsNumber = scalar @$measures;

        # it seems like some projects dont have a code coverage configured
        if ($measuresAsNumber > 0) {
            my $coverageMetric = $coverageResponse->{component}->{measures}->[0]->{value};
            if ($coverageMetric > 50) {
                $projectsWithCoverage50++;
            } else {
                $projectsWithoutCoverage++;
            }
        } else {    
            $projectsWithoutCoverage++;
        }

        # METRIC: How many security Vulnerabilities per project, per server
        $url = $top_url . $key . "/api/issues/search?componentKeys=$projectKey&statuses=OPEN&severities=BLOCKER,CRITICAL,MAJOR";
        my $issuesRes    = `curl $options "$url"`;
        $issuesRes       = $json->decode($issuesRes);
        my $openIssues   = $issuesRes->{issues};
        $openIssues      = scalar @$openIssues;
        $openIssuesTotal += $openIssues;
    }

    # METRIC: What kind of code is scanned (how many Java projects vs other code, per instance)
    $url = $top_url . $key . "/api/languages/list";
    my $languages = `curl $options "$url"`;
    $languages = $json->decode($languages);
    $languages = $languages->{languages};
    my $langString = "";
    
    foreach my $lang (@{$languages}) {
        # TODO: add another method or condition to remove the comma from last item
        $langString = $langString . $lang->{name} . ', ';
    }

    print "$key,UP,$sonar_version,YES,$last_scan,$projectsTotal,$openIssuesTotal,$projectsWithoutQualityGate,$projectsQualityGateError,$projectsQualityGateSuccess,$projectsWithoutCoverage,$projectsWithCoverage50,\"$langString\",$desc\n";
}
exit 0;
