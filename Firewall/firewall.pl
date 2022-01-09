#!/usr/bin/perl -w

use Socket;
use File::Basename;

our $ROOT = dirname(__FILE__);
our $UFW="/usr/sbin/ufw";
our $FWRF="firewall.rules";
my $DEBUG=1;

`echo y | $UFW enable`;
`echo y | $UFW default deny`;
&ReadFirewallRulesFile("$ROOT/$FWRF");

sub ReadFirewallRulesFile {
   my ($fwrf) = @_;
   my %SIGS;
   # Read firewall.rules file line by line
   open(FILE, "< $fwrf") or die "Can't read file '$fwrf' [$!]\n";
   while ($line = <FILE>) {
      # Remove spacing, ignore comments, remove newlines
      $line =~ s/#.*//g;
      $line =~ s/^\s+(.*?)\s+$/$1/g;
      next if $line =~ /^$/;

      # host,host,host:proto:port,proto:port
      ($hosts, $protos) = $line =~ m/^([^:]+):(.*)$/;
      &DEBUG("Hosts: $hosts");

      foreach my $host (split /\s*,\s*/, $hosts) {
         &DEBUG("Host: $host");
         foreach my $protoport (split /,/, $protos) {
            # TODO: Support both protocols by port only?
            my ($proto, $port) = $protoport =~ /([^:]+):(\d+)/;
            &DEBUG("Proto: $proto, Port: $port");

            my $signature = "SIG:$host:$proto:$port";
            my $ip = $host;
               $ip = inet_ntoa(inet_aton($host)) if ($host ne '*');# if ($host !~ m/^($RE{net}{IPv4}|$RE{net}{IPv6})$/);

            &AddOrUpdate($signature, $ip, $proto, $port);

            $SIGS{$signature} = 0;
         }
      }
   }
   close (FILE);
   &DeleteRest(\%SIGS);
}


sub AddOrUpdate {
   my ($signature, $ip, $proto, $port) = @_;
   &DEBUG("ADD OR UPDATE: $signature, $ip, $proto, $port");
   my $fw = `$UFW status numbered`;
   my $found = 0;
   my $mod = 1;
   foreach my $fwline (reverse split /\n/, $fw) {
      if ($fwline =~ m/^\s*\[\s*(?<id>\d+)\s*\]\s+(?<port>\d+)(\/(?<proto>\S+))?\s+(?:\(v6\))?\s+ALLOW IN\s+(?<from>[^#\n]+?)\s+#\s+\Q$signature\E$/gm) {
         $found = 1;
              my ($e_id, $e_port, $e_proto, $e_ip) = ($+{id}, $+{port}, $+{proto}, $+{from});
              $e_ip = "*" if ($e_ip =~ m/^Anywhere/);
           &DEBUG("Already exists: [$e_id] $e_port/$e_proto $e_ip");
              if ($e_ip eq $ip && $e_proto eq $proto && $e_port eq $port) {
            $mod = 0;
                 &DEBUG("No change: [$e_id] $e_port/$e_proto $e_ip");
            # Same, so return
            # TODO: We should clean duplicates.
            return;
         }
         # Rule needs updating, so we delete it and insert new
              &INFO("Change, deleting old rule: [$e_id] $e_port/$e_proto $e_ip");
         print `echo y | $UFW delete $e_id`;
      }
   }
   #return if ($found eq 1 && $mod eq 0);

   # Add new rule
   &INFO("Adding new rule: $port/$proto $ip");
   $ip = "any" if ($ip eq "*");
   &DEBUG("$UFW allow from $ip to any port $port proto $proto comment '$signature'");
   print `$UFW allow from $ip to any port $port proto $proto comment '$signature'`
}

sub DeleteRest {
   my %sig = %{shift()};
   my $fw = `$UFW status numbered`;

   foreach my $fwline (reverse split /\n/, $fw) {
      if ($fwline =~ m/^\s*\[\s*(?<id>\d+)\s*\]\s+(?<port>\d+)(\/(?<proto>\S+))?\s+(?:\(v6\))?\s+ALLOW IN\s+(?<from>[^#\n]+?)\s+#\s+(?<signature>SIG:.*?)\s*$/gm) {
         my ($e_id, $e_port, $e_proto, $e_ip, $e_signature) = ($+{id}, $+{port}, $+{proto}, $+{from}, $+{signature});
         unless (exists $sig{$e_signature}) {
            &INFO("Removing rule #$e_id: $fwline");
            print `echo y | $UFW delete $e_id`;
         }
      }
   }
}

sub DEBUG { print "[DEBUG] ".shift."\n" if ($DEBUG); }
sub INFO { print "[INFO] ".shift."\n"; }
sub ERROR { print "[ERROR] ".shift."\n"; }
