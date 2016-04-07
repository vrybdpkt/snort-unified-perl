#!/usr/bin/perl
#https://github.com/Magikman/SuricataTools/blob/master/unified2Parser.pl

## Modules
##--------
use warnings;
use strict;
use POSIX qw(strftime);
use File::Copy;
use English;
use Date::Manip;
use lib './SnortUnified';
use SnortUnified qw(:ALL);
use SnortUnified::MetaData qw(:ALL);
use SnortUnified::TextOutput qw(:ALL);


##Variables
##-----------
chomp(my $hostname = `hostname -s`);		
my $pcapDir="./pcaps/"; 			#Where should we write pcaps to?
my $logDir="/var/log/suricata/"; 				#Where can we find the unified2 logs?
#my $logDir="./logs/"; 				#Where can we find the unified2 logs?
my $oldLogs="$logDir"."old/"; 			#Where do we move the unified2 logs?
my $cefOut='./ceflog.log'; 			#Where we we write the CEF log?
my $fastOut='./fast.log'; 			#Where should we write the fast.log to?
my $waldoFile="./$hostname.waldo"; 		#WHERE'S WALDO? :) 
my $nc = '/bin/nc';				#The swiss army knife of tcp/ip
my $pidFile="./$hostname.barnyard.pid"; 		#Where should the pid file go?
my $UF_Data;
my $recordTypes = {
	7 => 'IPv4AlertData',
	2 => 'IPv4Packet',
	72 => 'IPv6AlertData',
};
my $IP_PROTO_NAMES = {
	4 => 'IP',
	1 => 'ICMP',
	2 => 'IGMP',
	94 => 'IPIP',
	6 => 'TCP',
	17 => 'UDP',
	47 => 'GRE',
	41 => 'IPv6',
};

my $debug = 0;

# Subroutines
#------------
sub parseLog($);
sub printPCAPHeader($);
sub statusLog($$);
sub decIpToDotted($);
sub statusCheck();
sub handleLog($);
sub cleaner();
sub findOldest($);

#Exit cleanly if user requests it
$SIG{'TERM'}=\&cleaner;
$SIG{'INT'}=\&cleaner;

#I don't want to call these but once...so they go here
my $sids = get_snort_sids("/etc/suricata/sid-msg.map","/etc/suricata/gen-msg.map");
my $class = get_snort_classifications("/etc/suricata/classification.config");

sub parseLog($)
{
	my $file=shift;
	my $waldo;
	if(!defined($UF_Data))
	{	
		if($debug) { statusLog('DEBUG',"Opening log file: $$file"); }
		$UF_Data = openSnortUnified($logDir.$$file);
	}
	if ( $UF_Data->{'TYPE'} eq 'LOG' )
	{
		closeSnortUnified();
		die("$0 does not handle unified log files");
	}
	if( -f $waldoFile)
	{
		open(WLDO,"<","$waldoFile") or statusLog('WARN',"Can't open $waldoFile: $!\n");
		while(my $last = <WLDO>)
		{
			$waldo=$last;
		}
		close(WLDO);
	}
	else
	{
		open(WLDO,">","$waldoFile") or statusLog('WARN',"Can't open $waldoFile: $!\n");
		WLDO->autoflush(1);
		print WLDO 1451606401; #Jan 1, 2016
		close(WLDO);
	}
	while( my $record = readSnortUnifiedRecord() )
	{
		#Default waldo. first run waldo will not be defined...would throw warning without this
		$waldo = 1451606401 unless(defined($waldo));
		#next record until we find waldo
		next unless($record->{'tv_sec'} >= $waldo);
		if(($record->{'TYPE'} == 7) || ($record->{'TYPE'} == 72))
		{#IPv4/IPv6 event
			handleLog(\$record);
		}
		elsif($record->{'TYPE'} == 2)
		{#Found a packet
			if($record->{'linktype'} == 1)
			{#ethernet
				if(!-f "$pcapDir"."$record->{'sensor_id'}"."$record->{'event_id'}"."$record->{'tv_sec'}".".pcap")
				{#Create PCAP with initial packet
					#if($debug) { statusLog('DEBUG',"Creating $pcapDir"."$record->{'event_id'}.pcap"." with a linktype of $record->{'linktype'} "); }
					open(my $PCAP,">","$pcapDir"."$record->{'sensor_id'}"."$record->{'event_id'}"."$record->{'tv_sec'}".".pcap") or statusLog('FATAL',"Can't open PCAP for writing: $!");
					binmode($PCAP);
					printPCAPHeader($PCAP);
					print $PCAP pack("L",$record->{'pkt_sec'});
					print $PCAP pack("L",$record->{'pkt_usec'});
					print $PCAP pack("L",$record->{'pkt_len'});
					print $PCAP pack("L",$record->{'pkt_len'});
					print $PCAP $record->{'pkt'};
					close($PCAP);
				}
				elsif(-f "$pcapDir"."$record->{'sensor_id'}"."$record->{'event_id'}"."$record->{'tv_sec'}".".pcap")
				{#Add packet to pcap
					#if($debug) { statusLog('DEBUG',"Adding a packet to $pcapDir"."$record->{'event_id'}.pcap with a linktype of "."$record->{'linktype'} "); }
					open(my $PCAP,">>","$pcapDir"."$record->{'sensor_id'}"."$record->{'event_id'}"."$record->{'tv_sec'}".".pcap") or statusLog('FATAL',"Can't open PCAP for writing: $!");
					binmode($PCAP);
					print $PCAP pack("L",$record->{'pkt_sec'});
					print $PCAP pack("L",$record->{'pkt_usec'});
					print $PCAP pack("L",$record->{'pkt_len'});
					print $PCAP pack("L",$record->{'pkt_len'});
					print $PCAP $record->{'pkt'};
					close($PCAP);
				}
			}
			elsif($record->{'linktype'} == 12)
			{#DLT_RAW Raw IP packet. Need to rebuild L2. Need to add logic to adjust 0800 when dealing with IPv6
				my $srcMac='38eaa78eb06d';
				my $dstMac='d89d672af7dc';
				my $length=$record->{'pkt_len'}+14;
				if(!-f "$pcapDir"."$record->{'sensor_id'}"."$record->{'event_id'}"."$record->{'tv_sec'}".".pcap")
				{#Create initial PCAP
					if($debug) { statusLog('DEBUG',"Creating $pcapDir"."$record->{'event_id'}.pcap"." with a linktype of $record->{'linktype'} "); }
					open(my $PCAP,">","$pcapDir"."$record->{'sensor_id'}"."$record->{'event_id'}"."$record->{'tv_sec'}".".pcap") or statusLog('FATAL',"Can't open PCAP for writing: $!");
					binmode($PCAP);
					printPCAPHeader($PCAP);
					print $PCAP pack("L",$record->{'pkt_sec'});
					print $PCAP pack("L",$record->{'pkt_usec'});
					print $PCAP pack("L",$length);
					print $PCAP pack("L",$length);
					print $PCAP pack('H12',$dstMac);
					print $PCAP pack('H12',$srcMac);
					print $PCAP pack('H4','0800');
					print $PCAP $record->{'pkt'};
					close($PCAP);
				}
				elsif(-f "$pcapDir"."$record->{'sensor_id'}"."$record->{'event_id'}"."$record->{'tv_sec'}".".pcap")
				{#Add packet to PCAP
					if($debug) { statusLog('DEBUG',"Adding a packet to $pcapDir"."$record->{'event_id'}.pcap with a linktype of "."$record->{'linktype'} "); }
					open(my $PCAP,">>","$pcapDir"."$record->{'sensor_id'}"."$record->{'event_id'}"."$record->{'tv_sec'}".".pcap") or statusLog('FATAL',"Can't open PCAP for writing: $!");
					binmode($PCAP);
					print $PCAP pack("L",$record->{'pkt_sec'});
					print $PCAP pack("L",$record->{'pkt_usec'});
					print $PCAP pack("L",$length);
					print $PCAP pack("L",$length);
					print $PCAP pack('H12',$dstMac);
					print $PCAP pack('H12',$srcMac);
					print $PCAP pack('H4','0800');
					print $PCAP $record->{'pkt'};
					close($PCAP);
				}
			}
		}
		elsif(!defined($recordTypes->{$record->{'TYPE'}}))
		{#Log exceptions. 
			statusLog('WARN',"Unknown record type: $record->{'TYPE'}");
		}
		#Waldo
		open(WLDO,">",$waldoFile) or statusLog('WARN',"Unable to open $waldoFile for writing\n");
		WLDO->autoflush(1);
		$waldo=$record->{'tv_sec'};
		print WLDO $record->{'tv_sec'};
		close(WLDO);
	}
	if($debug) { statusLog('DEBUG',"Entering process loop...calling findNewLogs..."); }
	my $val = findOldest(\$$file);
	if($val ne "false")
	{
		closeSnortUnified();
		$UF_Data=undef;
		statusLog('INFO',"Found a new file:$$val. Recalling parseLog and moving the log file to $oldLogs"); 
		move("$logDir$$file","$oldLogs$$file") or statusLog('WARN',"Unable to move the old log: $!");
		parseLog(\$$val);
	}
	else
	{
		statusLog('INFO',"Calling parseLog with same file, nothing new");
		parseLog(\$$file);	
	}
	return;
	
}

sub handleLog($)
{#sub to send CEF event. Will need to modify the prototype
	my $event=shift;
	my $time = strftime("%m/%d-%H:%M:%S", gmtime($$event->{'tv_sec'}));
	my $zeros=6-length($$event->{'tv_usec'});
	my $pad;
	my $pcapName="$$event->{'sensor_id'}"."$$event->{'event_id'}"."$$event->{'tv_sec'}".".pcap";
	if($zeros > 0)
	{	
		 $pad='0' x $zeros;
	         $time.=".$pad"."$$event->{'tv_usec'}";
	}
	else
	{
		$time.=".$$event->{'tv_usec'}";
	}
	#print "$time\n";
	if(!defined($IP_PROTO_NAMES->{$$event->{'protocol'}}))
	{
		statusLog('WARN',"Unknown protocol: $$event->{'protocol'}");
	}
	my $msg = sprintf("%s [**] [%d:%d:%d] %s [**] [Classification ID: %s] [Priority ID: %d] {%s} %s:%d -> %s:%d [PCAPName=%s] [Sensor-ID=%d]\n",
			$time, 
			$$event->{'sig_gen'},
			$$event->{'sig_id'},
			$$event->{'sig_rev'},
			get_msg($sids,$$event->{'sig_gen'},$$event->{'sig_id'},$$event->{'sig_rev'}),
			get_class($class,$$event->{'class'}),
			get_priority($class,$$event->{'class'},$$event->{'priority'}),
			$IP_PROTO_NAMES->{$$event->{'protocol'}},
			decIpToDotted($$event->{'sip'}),
			$$event->{'sp'},
			decIpToDotted($$event->{'dip'}),
			$$event->{'dp'},
			$pcapName,
			$$event->{'sensor_id'},
);
	open(FAST,">>","$fastOut") or statusLog('FATAL',"Can't open $fastOut for writing: $!\n");
	FAST->autoflush(1);
	print FAST $msg;
	close(FAST);

	my $cef=sprintf("CEF:0|Suricata|IDS|2.6|%d|%s|%d|5|rt=%d src=%s spt=%d dst=%s dpt=%d cat=%s cs1=%s cs1Label=PCAPName\n",
			$$event->{'sig_id'},
			get_msg($sids,$$event->{'sig_gen'},$$event->{'sig_id'},$$event->{'sig_rev'}),
			get_priority($class,$$event->{'class'},$$event->{'priority'}),
			$$event->{'tv_sec'},
			decIpToDotted($$event->{'sip'}),$$event->{'sp'},
			decIpToDotted($$event->{'dip'}),$$event->{'dp'},
			get_class($class,$$event->{'class'}),
			$pcapName
);
	open(CEF, ">>", "$cefOut") or statusLog('FATAL',"Can't open $cefOut for writing: $!\n");
	CEF->autoflush(1);
	print CEF "$cef";
	close(CEF);
	return;
}
sub printPCAPHeader($)
{#Global PCAP headers. Need to move all PCAP printing to here.
	my $fh=shift;
	print $fh pack("L",0xA1B2C3D4);
	print $fh pack("S",2);
	print $fh pack("S",4);
	print $fh pack("L",0);
	print $fh pack("L",0);
	print $fh pack("L",65535);
	print $fh pack("L",1);
	return;
}
sub statusLog($$)
{#Everyone needs logs
    my($level,$msg) = @_;
    open(STATUS,">>","./statusLog.log") or die "Can't open file for writing: $!\n";
    STATUS->autoflush(1);
	my @curTime=localtime;
    my $timeStamp = $curTime[5]+1900 . $curTime[4]+1 . $curTime[3] . $curTime[2];;
    my $logDate = UnixDate('today', "%Y%m%d");

    print STATUS "$logDate $timeStamp STATUS=[$level] HOST=[$hostname] MSG=[$msg]\n";

    if($level eq 'FATAL'){die "$PROGRAM_NAME FATAL ERROR=>$msg\n"}

    return;
}
sub decIpToDotted($) 
{#Why include Socket for this small function? IPv6...possibly. Need to figure out how to pack/unpack IPv6.
	my $decIp=shift;
	if($decIp =~ /\:/) { statusLog('INFO',"Found an IPv6 address");return $decIp; }
	my $dotted=join('.',unpack('C4',pack('N',$decIp)));
	return $dotted;
}
sub statusCheck()
{#Check to make sure we don't walk on each other
	my $pID;
	my @procs;
	if( -f $pidFile )
	{
		open(R,"<","$pidFile");
		while(<R>) { $pID = $_; }
		close(R);
		if(!defined($pID))
		{
			print "No pid found in $pidFile for $hostname\n";
			open(R,">","$pidFile");
			print R $PID;
			close(R);
		}
		else
		{
			print "Checking if $pID is valid...\n";
			@procs=`ps aux | grep $pID | egrep -v 'vim|grep'`;
			if(scalar(@procs) >= 1)
			{
				print "$0 is running with $pID\n";
				exit 1;
			}
			else
			{
				print "$pID is not a valid PID\n";
				unlink($pidFile);
				open(R,">","$pidFile");
				print R $PID;
				close(R);
			}
		}
	}
	else
	{
		open(R,">","$pidFile");
		print R $PID;
		close(R);
	}
	return;
}
sub cleaner()
{#No one likes to leave trash on the ground, right?
	closeSnortUnified();
	unlink($pidFile);
	$UF_Data=undef;
	statusLog('INFO',"Log parser exiting");
	exit 0;
}

sub findOldest($)
{#Find oldest file that is not the current file
	my $curFile=shift;
	my $fileMask=$logDir."unified2";
	my @ls = <$fileMask*>;
	my @return;
	use File::Basename;
	if(defined($curFile))
	{
		if(scalar(@ls) > 1)
		{
			@return=sort{$b cmp $a}(@ls);
			foreach my $file(@return)
			{
				if($$curFile ne basename($file))
				{
					return(\basename($file));
				}
			}
		}
		elsif(scalar(@ls) == 1)
		{
			return \basename($ls[0]) unless($ls[0] =~ $$curFile);
		}			
	}
	else
	{
		if(scalar(@ls) > 1)
		{
			@return=sort{$b cmp $a}(@ls);
			return \basename($return[0]);
		}
		elsif(scalar(@ls) == 1)
		{
			return \basename($ls[0]);
		}
	}
	return "false";
}
sub main()
{#Main
	statusCheck();
	statusLog('INFO',"Starting log parser");
	if(findOldest(undef) eq "false")
	{
		print "No log files found in: $logDir\n";
		unlink($pidFile);
		exit 1;
	}
	else
	{
		parseLog(findOldest(undef));
	}
	statusLog('INFO',"Log parser exiting");
	close(STATUS);
	unlink($pidFile);
	return;
}
main();	
