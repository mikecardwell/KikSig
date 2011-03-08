#!/usr/bin/perl

##############################################################################
#                                                                            #
# Copyright 2011, Mike Cardwell, Contact info @ https://grepular.com/        #
#                                                                            #
# This program is free software; you can redistribute it and/or modify       #
# it under the terms of the GNU General Public License as published by       #
# the Free Software Foundation; either version 2 of the License, or          #
# any later version.                                                         #
#                                                                            #
# This program is distributed in the hope that it will be useful,            #
# but WITHOUT ANY WARRANTY; without even the implied warranty of             #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              #
# GNU General Public License for more details.                               #
#                                                                            #
# You should have received a copy of the GNU General Public License          #
# along with this program; if not, write to the Free Software                #
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA #
#                                                                            #
##############################################################################

use strict;
use warnings;
use CGI;
use IO::Select;
use IO::Socket;

## IP address of Kiks XMPP service
	my $kik_xmpp_ip = '184.106.41.33';

## Prevent iptables commands from being repeated
	my $iptables_done = 0;

## Display usage information if run without arguments
	help() unless @ARGV;

## Parse arguments
	my( $debug, $port, $signature, $norepeat );
	{
		my @args = @ARGV;
		while( @args ){
			my $key = shift @args;
			if( $key eq '--help' || $key eq '-h' ){
				help();
			} elsif( $key eq '--debug' ){
				$debug = 1;
			} elsif( $key eq '--port' ){
				$port = shift @args;
				die "Invalid value for --port\n" if !defined $port || $port =~ /\D/;
			} elsif( $key eq '--no-repeat' ){
				$norepeat = shift @args;
				die "Invalid value for --no-repeat\n" if !defined $norepeat || $norepeat =~ /\D/;
			} elsif( $key eq '--signature' ){
				$signature = shift @args;
				die "Invalid value for --signature\n" unless defined $signature;
			}
		}
		die "Missing --port\n"      unless defined $port;
		die "Missing --signature\n" unless defined $signature;
		die "Missing --no-repeat\n" unless defined $norepeat;
	}

## Root check
        die "Must run as the root user so iptables rules can be added/removed\n" if $<;

## Set up a listener
	my $lsn = new IO::Socket::INET( ReuseAddr => 1, Listen => 10, LocalPort => $port ) or die $!;
	my $sel = new IO::Select( $lsn );

## Somewhere to cache information about the connections
	my %socks  = ();

## Add the iptables rule
	$SIG{INT} = sub { iptables(0) };
	END             { iptables(0) }
	iptables(1);

## The main loop. Listen for incoming connections, and data
	print "".localtime()." Listening for incoming connections\n";
	my %repeat_cache = ();
	while( my @ready = $sel->can_read ){
		foreach my $fh ( @ready ){
			if( $fh == $lsn ){
       				my $local = $lsn->accept;
				my $remote = new IO::Socket::INET( PeerAddr => $kik_xmpp_ip, PeerPort => 5222 );
				$sel->add( $_ ) foreach( $local, $remote );

				$socks{$local}  = { type => 'local',  other => $remote };
				$socks{$remote} = { type => 'remote', other => $local  };

			} else {
				my $bytes = sysread( $fh, my $buf, 10240 );

				if( $bytes ){
					if( $socks{$fh}{type} eq 'local' ){
						if( $buf =~ /^<k to="talk\.kik\.com" from="([^"]+)_[^\@]+\@talk\.kik\.com\/[^"]+"[^>]+>/ ){
							$socks{$fh}{user} = $1;
							print "".localtime()." Kik session opened for user $1\n";
						} elsif( $buf =~ /^(<message type="chat" to="([^"]+)_[^\@]+\@talk\.kik\.com" id="[^"]+"><body>)(.+)(<\/body>.+<\/message>)$/ ){
							my( $start, $user, $body, $end ) = ( $1, $2, $3, $4 );

							## Prune the repeat cache
							 	foreach( keys %repeat_cache ){
									 delete $repeat_cache{$_} if $repeat_cache{$_} <= time - $norepeat;
								}

							## Add the signature, unless --no-repeat prevents it
								if( exists $repeat_cache{"$socks{$fh}{user}\0$user"} ){
									print "".localtime()." Not adding signature to message from $socks{$fh}{user} to $user\n";
								} else {
									$buf = "$start$body -- ".CGI::escapeHTML($signature).$end;
									print "".localtime()." Adding signature to message from $socks{$fh}{user} to $user\n";
								}

							## Update the repeat cache
								$repeat_cache{"$socks{$fh}{user}\0$user"} = time;
						}
					}
	
					## Debug output

						if( $debug ){
							foreach( split(/\r?\n/,$buf) ){
								print $socks{$fh}{type} eq 'local' ? "=> $_\n" : "<= $_\n";
							}
						}

					## Forward on the traffic
					
						syswrite( $socks{$fh}{other}, $buf );
				} else {

					## Close the connection
				
						my $other = $socks{$fh}{other};
						my $user  = $socks{$fh}{user} || $socks{$other}{user};

						print "".localtime()." Kik session closed for user $user\n";

						foreach( $fh, $other ){
							$sel->remove( $_ );
							delete $socks{$_};
							$_->close;
						}
				}
			}
		}	
	}

sub iptables {
	my $status = shift;
	return if $status == $iptables_done;
	$iptables_done = $status;

	my $command = sprintf( 'iptables -t nat -%s PREROUTING -p tcp -d %s --dport 5222 -j REDIRECT --to-port %s',
		$status ? 'I' : 'D',
		$kik_xmpp_ip,
		$port
	);

	print "".localtime()." Executing: $command\n";
	system $command;
}

sub help {
	print << "END_HELP";
Usage: kiksig.pl --port 12345 --no-repeat 86400 --signature "Test Signature"

--help / -h : Display this information, and then exit.
--debug     : Prints out the entire XMPP communication as it happens
--port      : Required - The port to listen on
--no-repeat : Required - Don't add the signature to a message if it has already
              been added to one from a sender, to a recipient, within this
              period of time (seconds).
--signature : Required - The signature text to add to the end of the Kik message.
              It will be precedeed by the separator " -- "
END_HELP
	exit 0;
}
