#!/usr/bin/env perl6

use v6;

use Terminal::ANSIColor;

grammar Nmap {
    rule TOP {
	<.rn> ** 2
	<entry>+
	<.rn>
    }

    rule entry {
	Nmap scan report for <ip>
	Host is <.rn>
	[Scanned at <.rn>]?
	PORT STATE SERVICE
	\d+'/'[tcp|udp] <state> <.rn>
    };

    token ip { [\d+] ** 4 % '.' }
    token state { open | closed | filtered }
    regex rn { <-[\n]> * }
};

&shell.wrap: -> |capt {
    my Str $cmd = capt.list[0];
    log "shell", $cmd.lines, style => 'underline';
    callsame
}

sub nmap_filter(Str $targets, Int $port) {
    my $p = shell qq{ nmap -T5 -n -p "$port" "$targets" }, :out;
    my $out = $p.out.slurp-rest;

    Nmap.parse($out)<entry>
    ==> grep( *<state> eq 'open' )
    ==> map( ~*<ip> )
}

sub log(Str $pref, @lines, :$style = '') {
    my $fmt = colored("$pref", $style) ~ colored(':', 'red') ~ ' %s';
    note @lines.fmt: $fmt, "\n" if so @lines.elems;
}

sub exploit(Str $exploit, Str $target, Int $port, Str $flagre) {
    my $p = shell qq{ $exploit "$target" "$port" }, :out, :err;

    log "$exploit", $p.err.lines, style => 'bold';

    $p.out.lines
    ==> map({ $_ ~~ / [$<flags> = <$flagre>] + % [.*?] / ?? |$<flags> !! |[] })
    ==> map( ~* )
}

sub USAGE {
    say qq {
Usage:
  $*PROGRAM [--targets=<Str>] [--port=<Int>] [--flagre=<Str>] <exploit>

    --targets   Targets list. The format is the same as for nmap
    --port      Target port
    --flagre    Perl6 regex to find flags in <expoit> output
    }
}

sub MAIN(Str $exploit, Str :$targets = '127.0.0.0-2',
	 Int :$port = 8080, Str :$flagre = '<[flag]>+') {

    my @targets = nmap_filter $targets, $port;

    for @targets -> $target {
	my @flags = exploit $exploit, $target, $port, $flagre;
	log "flag", @flags, style => 'underline cyan on_black';
    }
}
