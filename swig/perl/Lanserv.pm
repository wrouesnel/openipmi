package Lanserv;

use FileHandle;
use IPC::Open2;
use IO::Handle;

my $top_builddir = $ENV{top_builddir};
if (not defined $top_builddir) {
    $top_builddir = "../..";
}
my $srcdir = $ENV{srcdir};
my $top_srcdir;
if (defined $srcdir) {
    $top_srcdir = "$srcdir/../..";
} else {
    $top_srcdir = "../..";
}
my $this_srcdir = $top_srcdir . "/swig/perl";
my $lanserv_conf = $this_srcdir . "/lan.conf";
my $lanserv_emu = $top_builddir . "/lanserv/ipmi_sim -c " . $lanserv_conf . " -x 'mc_setbmc 0x20'";

sub reader {
    my $self = shift;
    my $readfile = $self->{readfile};
    my $controlread = $self->{controlread};
    my $responsewrite = $self->{responsewrite};
    my @readq;
    my $buf = "";
    my $cbuf = "";
    my $inbuf;
    my $pos;
    my $cpos;
    my $count;
    my $rin;
    my $rout;

    $self->{at_newline} = 0;
    $self->{waiting_newline} = 0;
    $self->{waiting_data} = 0;

    while (1) {
	$rin = "";
	if (defined $readfile) {
	    vec($rin, fileno($readfile), 1) = 1;
	}
	if (defined $controlread) {
	    vec($rin, fileno($controlread), 1) = 1;
	}
	if ($rin eq "") {
	    # No files open, just quit.
	    exit 0;
	}

	select($rout=$rin, undef, undef, undef);

	if (defined($readfile) && (vec($rout, fileno($readfile), 1) == 1)) {
	    $count = sysread $readfile, $inbuf, 128;
	    if ($count == 0) {
		close $readfile;
		undef $readfile;
		if (buf ne "") {
		    $buf = $buf . "\n";
		}
	    } else {
		$buf = $buf . $inbuf;
	    }

	    $cpos = index($buf, "> ");
	    if ($cpos eq 0) {
		# Got a prompt, let something be typed.
		if ($self->{waiting_newline}) {
		    # Tell the control connection I've got a newline
		    print $responsewrite "\n";
		    $self->{waiting_newline} = 0;
		} else {
		    $self->{at_newline} = 1;
		}
		$buf = substr($buf, 2);
	    }

	    $pos = index($buf, "\n");
	    while ($pos >= 0) {
		if ($pos eq 0) {
		    # ignore blank lines
		    $buf = substr($buf, 1);
		} else {
		    my $newline = substr($buf, 0, $pos);
		    $buf = substr($buf, $pos+1);
		    if ($self->{waiting_data}) {
			print $responsewrite $newline, "\n";
			$self->{waiting_data} = 0;
		    } else {
			push @readq, $newline;
		    }
		}

		$cpos = index($buf, "> ");
		if ($cpos eq 0) {
		    # Got a prompt, let something be typed.
		    if ($self->{waiting_newline}) {
			# Tell the control connection I've got a newline
			print $responsewrite "\n";
			$self->{waiting_newline} = 0;
		    } else {
			$self->{at_newline} = 1;
		    }
		    $buf = substr($buf, 2);
		}

		$pos = index($buf, "\n");
	    }
	}

	if (defined($controlread) && (vec($rout, fileno($controlread), 1) == 1)) {
	    $count = sysread $controlread, $inbuf, 128;
	    if ($count == 0) {
		close $controlread;
		undef $controlread;
	    } else {
		$cbuf = $cbuf . $inbuf;
		$pos = index($cbuf, "\n");
		while ($pos >= 0) {
		    if ($pos == 0) {
			# ignore blank lines
			$cbuf = substr($cbuf, 1);
		    } else {
			my $newline = substr($cbuf, 0, $pos);
			$cbuf = substr($cbuf, $pos+1);
			if ($newline eq "W") {
			    if ($self->{at_newline}) {
				print $responsewrite "\n";
				$self->{at_newline} = 0;
			    } else {
				# Give a newline response at the next prompt
				$self->{waiting_newline} = 1;
			    }
			} elsif ($newline eq "R") {
			    if (@readq == 0) {
				$self->{waiting_data} = 1;
			    } else {
				print $responsewrite shift @readq, "\n";
			    }
			} elsif ($newline eq "C") {
			    @readq = ();
			    print $responsewrite "\n";
			}
		    }
		    $pos = index($cbuf, "\n");
		}
	    }
	}
    }
}

sub cmdrsp {
    my $self = shift;
    my $cmd = shift;
    my $controlwrite = $self->{controlwrite};
    my $responseread = $self->{responseread};
    my $buf = "";
    my $inbuf;
    my $count;
    my $pos;

    print { $controlwrite } $cmd , "\n";
    $count = sysread $responseread, $inbuf, 128;
    while ($count) {
	$buf = $buf . $inbuf;
	$pos = index($buf, "\n");
	if ($pos >= 0) {
	    $buf = substr($buf, 0, $pos);
	    last;
	}
    }

    return $buf;
}

sub waitnextline {
    my $self = shift;
    return $self->cmdrsp("R");
}

sub clearlines {
    my $self = shift;
    $self->cmdrsp("C");
}

sub cmd {
    my $self = shift;
    my $cmd = shift;
    my $writefile = $self->{writefile};

    $self->cmdrsp("W");
    print { $writefile } $cmd . "\n";
}

sub close {
    my $self = shift;
    my $writefile = $self->{writefile};
    my $readfile = $self->{readfile};
    my $read_tid = $self->{read_tid};
    my $controlwrite = $self->{controlwrite};
    my $responseread = $self->{responseread};

    #$self->cmd("debug");
    $self->cmd("quit");
    close $writefile;
    close $readfile;
    close $controlwrite;
    close $responseread;
    waitpid($self->{child}, 0);
}

sub new {
    my %self : shared;
    local *CONTROLWRITE;
    local *CONTROLREAD;
    local *RESPONSEWRITE;
    local *RESPONSEREAD;
    local *READFILE;
    local *WRITEFILE;
    my $a;
    my $child;

    pipe(CONTROLREAD, CONTROLWRITE) || return;
    pipe(RESPONSEREAD, RESPONSEWRITE) || return;

    $child = open2(READFILE, WRITEFILE, "$lanserv_emu")
	|| return;

    $self->{child} = $child;
    $self->{readfile} = *READFILE;
    $self->{writefile} = *WRITEFILE;
    $self->{controlread} = *CONTROLREAD;
    $self->{controlwrite} = *CONTROLWRITE;
    $self->{responseread} = *RESPONSEREAD;
    $self->{responsewrite} = *RESPONSEWRITE;

    *CONTROLWRITE->autoflush(1);
    *RESPONSEWRITE->autoflush(1);

    bless $self;

    if ($child = fork) {
	# parent
	CORE::close READFILE;
	CORE::close RESPONSEWRITE;
	CORE::close CONTROLREAD;
    } elsif (defined $child) {
	# child
	CORE::close WRITEFILE;
	CORE::close RESPONSEREAD;
	CORE::close CONTROLWRITE;
	$self->reader();
    } else {
	CORE::close READFILE;
	CORE::close WRITEFILE;
	CORE::close RESPONSEWRITE;
	CORE::close CONTROLREAD;
	CORE::close RESPONSEREAD;
	CORE::close CONTROLWRITE;
	waitpid($child, 0);
	return undef;
    }

    $self->cmd("noecho");
    $self->cmd("persist off");
    #$self->cmd("debug msg");
    $self->waitnextline();

    return $self;
}
