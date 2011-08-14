#!/usr/bin/perl -I..

###############################################################################
# Copyright (c) 2007-11 Jason Brvenik.
# A Perl module to make it easy to work with snort unified files.
# http://www.snort.org
# 
# Basic barnyard like functionality
###############################################################################
# 
#
# The intellectual property rights in this program are owned by 
# Jason Brvenik.  This program may be copied, distributed and/or 
# modified only in accordance with the terms and conditions of 
# Version 2 of the GNU General Public License (dated June 1991).  By 
# accessing, using, modifying and/or copying this program, you are 
# agreeing to be bound by the terms and conditions of Version 2 of 
# the GNU General Public License (dated June 1991).
#
# This program is distributed in the hope that it will be useful, but 
# WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License 
# along with this program; if not, write to the 
# Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, 
# Boston, MA  02110-1301  USA 
# 
# 
#
###############################################################################

use SnortUnified qw(:ALL);
use SnortUnified::Database qw(:ALL);
use SnortUnified::MetaData(qw(:ALL));
use SnortUnified::TextOutput(qw(:ALL));
use Getopt::ArgvFile(qw(argvFile));
use Getopt::Long;

# $file = shift;
$UF_Data = {};
$record = {};

argvFile();

$result = GetOptions ("sid-msg|sids|S=s"         => \$sidmap,
                      "gen-msg|gids|G=s"         => \$gidmap, 
                      "classification|C=s"       => \$classfile,
                      "file|unified|f|U=s"       => \$file,
                      "username|u=s"             => \$user,
                      "password|p=s"             => \$pass,
                      "hostname|h=s"             => \$hostname,
                      "interface|i=s"            => \$interface,
                      "filter|F=s"               => \$filter,
                      "database|d=s"             => \$db,
                      "help|?"                   => \&usage,
                      "debug|D"                  => \$debug);

print License . "\n" if $debug;

if (checkParams() > 0) {
    usage();
    exit;
};


$sids = get_snort_sids($sidmap,$gidmap);
$class = get_snort_classifications($classfile);

# If you want to see them
print_snort_sids($sids) if $debug;

# If you want to see them
print_snort_classifications($class) if $debug;

# To use mssql you need to set up ODBC
# and do use it by changing the type to ODBC::mssql

# Set the connection type to ODBC
# setSnortConnParam('type', "ODBC::mssql");

# Set connection type tp mysql (default)
# setSnortConnParam('type', "mysql");

setSnortConnParam('user', $user);
setSnortConnParam('password', $pass);
setSnortConnParam('interface', $interface);
setSnortConnParam('database', $db);
setSnortConnParam('hostname', $hostname);
setSnortConnParam('filter', $filter);

die unless getSnortDBHandle();

my $sensor_id = getSnortSensorID();
my $uf_file = undef;
my $old_uf_file = undef;

printSnortConnParams() if $debug;
printSnortSigIdMap() if $debug;


$uf_file = get_latest_file($file) || die "no files to get";
die unless $UF_Data = openSnortUnified($uf_file);

# This loops forever looking for files and processes them
while (1) {
  $old_uf_file = $uf_file;
  $uf_file = get_latest_file($file) || print "no files to get" if $debug;
  
  if ( $old_uf_file ne $uf_file ) {
    closeSnortUnified();
    $UF_Data = openSnortUnified($uf_file) || die "cannot open $uf_file";
  }
  read_records();
}

sub read_records() {
  while ( $record = readSnortUnifiedRecord() ) {
    if ( $UF_Data->{'TYPE'} eq 'UNIFIED2' ) {
       if ( $record->{'TYPE'} eq $UNIFIED2_EVENT || 
            $record->{'TYPE'} eq  $UNIFIED2_IDS_EVENT ) {
        print_alert($record,$sids,$class) if $debug;
		insertSnortAlert($record,$sids,$class);
       } 
       if ( $record->{'TYPE'} eq $UNIFIED2_PACKET ) {
        print_log($record,$sids,$class) if $debug;
		insertSnortLog($record,$sids,$class);
       } 
    } else {
      #old school unified files should be long gone these days but JIC
      if ( $UF_Data->{'TYPE'} eq 'LOG' ) {
        print_log($record,$sids,$class) if $debug;
		insertSnortLog($record,$sids,$class);
      } else {
        print_alert($record,$sids,$class) if $debug;
		insertSnortAlert($record,$sids,$class);
      }
    }
  }
  return 0;
}

# clean up
closeSnortUnified();
closeSnortDBHandle();

sub get_latest_file($) {
  my $filemask = shift;
  my @ls = <$filemask*>;
  my $len = @ls;
  my $uf_file = "";


  if ($len) {
    # Get the most recent file
    my @tmparray = sort{$b cmp $a}(@ls);
    $uf_file = shift(@tmparray);
  } else {
    $uf_file = undef;
  }
  return $uf_file;
}

sub checkParams() {

    $quit = 0;

    if ( $debug ) {
        print "DEBUG IS ON\n";
    }

    if ( !$sidmap ) {
      print "The path to the sid-msg.map file is required. " . 
             "Use --sig-msg or -S\n";
        $quit = 1;
    }
    if ( !$gidmap ) {
        print "The path to the gen-msg.map file is required. " . 
               "Use --gen-msg or -G\n";
        $quit = 1;
    }
    if ( !$classfile ) {
        print "The path to the classifications file is required. " .
              "Use --classification or -C\n";
        $quit = 1;
    }
    if ( !$file ) {
        print "The path and mask to the unified files are required. " . 
              "Use --file or -f\n";
        $quit = 1;
    }
    if ( !$user ) {
        print "A username for the database is required. " .
               "Use --username or -u\n";
        $quit = 1;
    }
    if ( !$pass ) {
        print "A password for the database is required. " .
               "Use --password or -p\n";
        $quit = 1;
    }
    if ( !$hostname ) {
        print "A hostname (or ip) for the database is required. " .
               "Use --hostname or -h\n";
        $quit = 1;
    }
    if ( !$db ) {
        print "A database is required. " . 
               "Use --database or -d\n";
        $quit = 1;
    }
	if ( !$interface ) {
	    $interface = "NULL";
	}
	if ( !$filter ) {
	    $filter = "NULL";
	}

    return $quit;
}

sub usage() {

###############################################################################
  print <<EOT;
  
  $0 is a "barnyard like" utility for processing snort unified files
  $0 [options]

  Required parameters:
  --sid-msg or -S to specify the sid-msg.map file
  --gen-msg or -G to specify the gen-msg.map file
  --classification -C to specify the classification file
  --file or -f to specify which unified files to use
  --username or -u to specify the db user name
  --password or -p to speficy the password for --username
  --hostname or -h to specify the database host
  --database or -d to specify the name of the database to connect to
  
  Optional parameters:
  --interface or -i to speficy the interface for use when inserting events
  --filter or -F to specify a filter to use when inserting events
  --help or -? print this usage
  --debug or -D to turn on debugging

  Examples:
  $0 -S /etc/snort/sid-msg.mag -G /etc/snort/gid-msg.map \\
     -C /etc/snort/classification.conf -u snort -p passy \\
     -h localhost -d snortdb -f /var/log/snort/snort-unified*

  $0 -S /etc/snort/sid-msg.mag -G /etc/snort/gid-msg.map \\
     -C /etc/snort/classification.conf -u snort -p passy \\
     -h localhost -d snortdb -f /var/log/snort/snort-unified* \\
     -i eth1 -f "not host 10.1.1.1" -D

  $0 @/etc/snort/barnyard.conf

  Notes:
  You can also place the command line options into a configuration file and 
  point to it using ithis syntax "$0 @/path/to/barnyard.conf"

  NOTE: file (--file or -f) can be a full name or a mask
  if it is a file mask the latest file matching the mask will be processed
  EG: /var/snort/unified.log.12345678 to process a single file
      /var/snort/unified.log.* to process the latest file matching the mask

  $0 will follow the last file matching the mask one until a new one appears
  in this way you can have a process running continually inserting events as 
  they appear.

  - Moving old files to an archive etc is left as an exercise to the user.
  - Not reprocessing files is left as an exercise for the user but note that 
    processing a file again will just result in insert failures and is not fatal
  - If you have a directory of files you want to process to "catch up" then you
    will need to process them one at a time until things are caught up

EOT
  exit;
}
