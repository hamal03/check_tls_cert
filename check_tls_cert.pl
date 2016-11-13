#!/usr/bin/perl

# check_tls_cert.pl
# (c) Rob S. Wolfram <propdf@hamal.nl>
# Distributable under conditions of the GPL Version 2 or later
#
# Changelog
# 2016-11-12 - v1.0 - first working version
# 2016-11-13 - v1.1 - added DN/CN/HPKP checking

use strict;
use warnings;
use IPC::Run qw( run timeout );
use Time::ParseDate;
use Getopt::Long;
use Pod::Usage;

my ($STAT_OK,$STAT_WRN,$STAT_CRT,$STAT_UNK)=(0,1,2,3);
my ($OPTIONS,$OPENSSL,$CERTFILE,$SERVER,$PORT,$PROTO,$NAME,$WARN,$CRIT,$HELP);
my ($SHA256,$CN,$DN);
$OPENSSL="/usr/bin/openssl";
$PROTO="https";
$WARN=30;
$CRIT=7;
$!=$STAT_UNK; # errorvalue when die()ing

Getopt::Long::Configure ("bundling");
GetOptions('openssl|O=s' => \$OPENSSL,
           'certfile|f=s' => \$CERTFILE,
           'server|s=s' => \$SERVER,
           'port|p=i' => \$PORT,
           'proto|P=s' => \$PROTO,
           'servername|n=s' => \$NAME,
           'dn|D=s' => \$DN,
           'cn|C=s' => \$CN,
           'sha256|hpkp|S=s' => \$SHA256,
           'warning|w=i' => \$WARN,
           'critical|c=i' => \$CRIT,
           'help|h' => \$HELP)
   or pod2usage(-verbose => 0, -exitval => $STAT_UNK);
pod2usage(-verbose => 1) if ($OPTIONS);
pod2usage(-verbose => 2) if ($HELP);
die "Cannot execute openssl\n" if (not -f $OPENSSL or not -x $OPENSSL);

my %protoport=(https => 443, tls => 0, imaps => 993, ldaps => 663, ftps => 990,
    stls_smtp => 25, stls_pop3 => 110, stls_imap => 143, stls_ftp => 21);

my $cert;
open my $ERR, ">", "/dev/null";

if (defined $CERTFILE) {
    die "Cannot read certificate file\n" if (not -f $CERTFILE or not -r $CERTFILE);
    local $/=undef;
    open my $CRT, "<", $CERTFILE;
    $cert=<$CRT>;
    close $CRT;
}
else {
    if (not exists $protoport{$PROTO}) {
        die "Unknown protocol: $PROTO\n";
    }
    if (not defined $SERVER) {
        die "Server not specified\n";
    }
    $PORT=$protoport{$PROTO} if (not defined $PORT);
    die "Specify a port for generic TLS" if (not $PORT);
    my @sclt=($OPENSSL,"s_client","-connect","${SERVER}:${PORT}");
    if ($PROTO eq "https" and defined $NAME) {
        push @sclt, ("-servername", $NAME);
    }
    elsif ($PROTO eq "stls_smtp") {
        push @sclt, ("-starttls", "smtp");
    }
    elsif ($PROTO eq "stls_pop3") {
        push @sclt, ("-starttls", "pop3");
    }
    elsif ($PROTO eq "stls_imap") {
        push @sclt, ("-starttls", "imap");
    }
    elsif ($PROTO eq "stls_ftp") {
        push @sclt, ("-starttls", "ftp");
    }
    open my $IN, "<", "/dev/null";
    run(\@sclt,\*$IN,\$cert,\*$ERR,timeout(30));
    die "Openssl s_client failed\n" if ($?);
    close $IN;
}
my @x509=($OPENSSL,"x509","-noout");

#Check correct certificate first
if (defined $DN or defined $CN) {
    my @subj=(@x509,"-subject");
    my $subj;
    run(\@subj,\$cert,\$subj,\*$ERR,timeout(1));
    die "Invalid certificate\n" if ($?);
    chomp $subj;
    $subj =~ s/^subject\s*=\s*//i;
    if (defined $DN) {
        if (lc($subj) ne lc($DN)) {
            print "CRITICAL: Invalid distinguished name\n";
            exit $STAT_CRT;
        }
    }
    else {
        if (not $subj =~ /\/CN=$CN/i) {
            print "CRITICAL: incorrect common name\n";
            exit $STAT_CRT;
        }
    }
}
if (defined $SHA256) {
    # calculate the pin
    my @pubkey=(@x509,"-pubkey");
    my $pubkey;
    run(\@pubkey,\$cert,\$pubkey,\*$ERR,timeout(1));
    die "Invalid certificate\n" if ($?);
    my @der=($OPENSSL,"rsa","-pubin","-outform","der");
    my $der;
    run(\@der,\$pubkey,\$der,\*$ERR);
    my @dgst=($OPENSSL,"dgst","-sha256","-binary");
    my $dgst;
    run(\@dgst,\$der,\$dgst,\*$ERR);
    my @base64=($OPENSSL,"enc","-base64");
    my $pin;
    run(\@base64,\$dgst,\$pin,\*$ERR);
    chomp $pin;
    if ($SHA256 ne $pin) {
        print "CRITICAL: certificate hash differs\n";
        exit $STAT_CRT;
    }
}

my @certdate=(@x509,"-enddate");
my $certdate;

run(\@certdate,\$cert,\$certdate,\*$ERR,timeout(1));
die "Invalid certificate\n" if ($?);

#catch multiline output
my @cdates=grep(/^notAfter=/,split("\n",$certdate));
die "No date in certificate\n" if (not scalar @cdates);
(my $cdate=$cdates[0]) =~ s/^notAfter=//;
my $certepoch=parsedate($cdate);
my $now=time();
if ($certepoch < $now) {
    print "CRITICAL: certificate has expired ";
    print int(($now-$certepoch)/86400)+1;
    print " day(s) ago ($cdate)\n";
    exit $STAT_CRT;
}
elsif (($certepoch-$CRIT*86400) < $now) {
    print "CRITICAL: certificate will expire in ";
    print int(($certepoch-$now)/86400);
    print " day(s) ($cdate)\n";
    exit $STAT_CRT;
}
elsif (($certepoch-$WARN*86400) < $now) {
    print "WARNING: certificate will expire in ";
    print int(($certepoch-$now)/86400);
    print " day(s) ($cdate)\n";
    exit $STAT_WRN;
}
else {
    print "Certificate will expire on $cdate\n";
    exit $STAT_OK;
}


__END__

=head1 NAME

check_tls_cert.pl - Check the expiration date (and optionally the correctness)
of a TLS certificate

=head1 SYNOPSIS

B<check_tls_cert.pl> B<-f>|B<--certfile> I<filename> 
[B<-D>|B<--dn> I<distinguished name>] [B<-C>|B<--cn> I<FQDN>]
[B<-S>|B<--sha256>|B<--hpkp> I<base64 string>]
[B<-O>|B<--openssl> I<binary>] [B<-w>|B<--warning> I<days>] [B<-c>|B<--critical> I<days>] 

B<check_tls_cert.pl> B<-s>|B<--server> I<servername> [B<-P>|B<--proto> I<protocol>]
[B<-p>|B<--port> I<portnumber>] [B<-n>|B<--servername> I<fqdn>] 
[B<-D>|B<--dn> I<distinguished name>] [B<-C>|B<--cn> I<common name>]
[B<-S>|B<--sha256>|B<--hpkp> I<base64 string>]
[B<-O>|B<--openssl> I<binary>] [B<-w>|B<--warning> I<days>] [B<-c>|B<--critical> I<days>] 

B<check_tls_cert.pl> B<-h>|B<--help>

=head1 DESCRIPTION

This script will fetch a TLS (SSL) certificate remotely or read a file containing 
the certificate and determine when the certificate will expire. The script will output
a single line of text with the status and terminate with exit code 0, 1 or 2 depending
on the status. The script is to be used in a Nagios or compatible monitoring system.

The script can also check the correctness of the certificate, based either on the fully
qualified domain name (i.e., the "/CN" part of the subject), the distinguished name
(i.e., the full subject line) or the HPKP pin of the certificate (i.e., a base64
representation of the SHA256 hash of the public key part in DER format).

When retrieving the certificate remotely, it is also possible to retrieve the certificate
from servers that use the STARTTLS protocol and from web servers that use Server Name Indication
(SNI) to share the same IP address and port with other web servers.

=head1 REQUIREMENTS

The script requires the perl modules IPC::Run, Getopt::Long, Pod::Usage and 
Time::ParseDate and the openssl binary. The script assumes to
run on a unix-like operating system.

=head1 OPTIONS

=over 4

=item B<-f, --certfile> I<filename> 

Read the certificate from a local file. If this option is used, the options B<--server>,
B<--proto>, B<--port> and B<--servername> are ignored. Either this option or B<--server>
is mandatory.

=item B<-s, --server> I<servername> 

Connect remotely to the server indicated by I<servername>. Either a host name or IP address
will work. Either this option or B<--certfile> above is mandatory.

=item B<-p, --port> I<portnumber> 

Optionally specify the port number on which to connect to the server. If neither this option
nor the option B<--proto> below is specified, port 443 (the standard HTTPS port) is used.

=item B<-P, --proto> I<protocol>

Optionally specify the protocol that the server expects. This determines the port number and if 
the STARTTLS communication should be used. If the B<--port> option is used, it overrides the
implied port here. The available protocols are I<https> (default, connect to port 443), 
I<imaps> (connect to port 993), I<ftps> (connect to port 990), I<ldaps> (connect to port 663),
I<stls_smtp> (connect to port 25 using STARTTLS in SMTP), I<stls_pop3> (connect to port 110
using STARTTLS in POP3), I<stls_imap> (connect to port 143 using STARTTLS in IMAP),
I<stls_ftp> (connect to port 21 using STARTTLS in FTP) and I<tls> (TLS connection to a
mandatory specified port).

=item B<-n, --servername> I<fqdn>

When connecting to a https server, this option can be used to specify one of multiple webservers
that listens to the same connection (using SNI, Server Name Indication). This option is ignored
with all other protocols. To be able to use this, openssl version 1.0.1 or higher is required.
Older versions will yield an error. 

=item B<-D, --dn> I<distinguished name>

Optionally check the validity of the Subject: line of the cerificate. The
complete distinguished name should be provided (e.g.:
"/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=www.microsoft.com").
The check is case insensitive and a failure yields a critical status.

=item B<-C, --cn> I<FQDN>

Check the validity of the common name in the subject line (in the example of the previous item:
"www.microsoft.com". Only provide the fully qualified domain name, not the "/CN=" part. If
the B<--dn> option above is also provided, this option is ignored since the common name is part
of the subject name. A failure of this yields a critical status.

=item B<-S, --sha256, --hpkp> I<base64 string>

Optionally check the HPKP pin of the certificate. This is a base64 encoding of the sha256
hash, of a DER output of the certificate's public key. This is the same string that is used
in HTTP Public Key Pinning (HPKP). An incorrect string yields a critical status.
The base64 string can be calculated as follows:

    openssl x509 -in certificate_file -noout -pubkey | \
    openssl rsa -pubin -outform der | \
    openssl dgst -sha256 -binary | \
    openssl enc -base64

=item B<-O, --openssl> I<binary>

Specify the location of the openssl binary. This defaults to I</usr/bin/openssl>.

=item B<-w, --warning> I<days>

Specify the number of days (or less) until the certificate will expire which you deem worthy 
of a warning. The default is 30.

=item B<-c, --critical> I<days>

Specify the number of days (or less) until the certificate will expire which you consider
critical. The default is 7. A critical status takes precedence to a warning status.

=item B<-h, --help>

Print the manpage.

=item B<-o, --options>

Print a short help, consisting of Usage and Options.

=back

=head1 AUTHOR

Rob S. Wolfram E<lt>propdf@hamal.nlE<gt>

=head1 LICENSE

This program is licensed according to the GNU General Public License
(GPL) Version 2 or later. A copy of the license text can be obtained from
E<lt>http://www.gnu.org/licenses/gpl.htmlE<gt> or by mailing the
author. In short it means that there are no restrictions on its use, but
distributing the program or derivative works is only allowed according
to the terms of the GPL.

=cut

