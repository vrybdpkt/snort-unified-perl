#!/usr/bin/perl -I..

#########################################################################################
# Copyright (c) 2007 Jason Brvenik.
# A Perl module to make it easy to work with snort unified files.
# http://www.snort.org
# 
# Basic barnyard like functionality
#########################################################################################
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
#########################################################################################

use SnortUnified qw(:ALL);
use SnortUnified::Database qw(:ALL);
use SnortUnified::MetaData(qw(:ALL));
use Getopt::Long;

print License . "\n";

# $file = shift;
$UF_Data = {};
$record = {};

$result = GetOptions ("sid-msg|S=s"         => \$sidmap,
                      "gen-msg|G=s"         => \$gidmap, 
                      "classification|C=s"  => \$classfile,
                      "file|f=s"            => \$file,
                      "username|u=s"        => \$user,
                      "password|p=s"        => \$pass,
                      "hostname|h=s"        => \$host,
                      "interface|i=s"       => \$interface,
                      "filter|F=s"          => \$filter,
                      "database|d=s"        => \$db,
                      "debug|D"             => \$debug);


$sids = get_snort_sids($sidmap,$gidmap);
$class = get_snort_classifications($classfile);

# If you want to see them
print_snort_sids($sids) if $debug;

# If you want to see them
print_snort_classifications($class) if $debug;

setSnortConnParam('user', $user);
setSnortConnParam('password', $pass);
setSnortConnParam('interface', $interface);
setSnortConnParam('database', $database);
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

while (1) {
  $old_uf_file = $uf_file;
  $uf_file = get_latest_file($file) || die "no files to get";
  
  if ( $old_uf_file ne $uf_file ) {
    closeSnortUnified();
    $UF_Data = openSnortUnified($uf_file) || die "cannot open $uf_file";
  }

  read_records();
}

sub read_records() {
  while ( $record = readSnortUnifiedRecord() ) {
    if ( $UF_Data->{'TYPE'} eq 'UNIFIED2' ) {
       if ( $record->{'TYPE'} eq $UNIFIED2_EVENT || $record->{'TYPE'} eq  $UNIFIED2_IDS_EVENT ) {
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

