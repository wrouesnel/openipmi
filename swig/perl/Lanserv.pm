package Lanserv;

use FileHandle;
use IPC::Open2;
use IO::Handle;

my $top_builddir = "../..";
my $top_srcdir = "../..";
my $this_srcdir = $top_builddir . "/swig/perl";
my $lanserv_conf = $this_srcdir . "/lan.conf";
my $lanserv_emu = $top_builddir . "/lanserv/lanserv_emu -c " . $lanserv_conf;


sub reader {
    my $self = shift;
    my $atprompt_sem = $self->{atprompt_sem};
    my $readfile = $self->{readfile};
    my $readq = $self->{readq};
    my $readq_sem = $self->{readq_sem};
    my $buf = "";
    my $inbuf;
    my $pos;
    my $count;

    $count = sysread $readfile, $inbuf, 128;
    while ($count) {
 	$buf = $buf . $inbuf;
 	$pos = index($buf, "> ");
 	if ($pos eq 0) {
 	    # Got a prompt, let something be typed.
 	    $atprompt_sem->up(1);
 	    $buf = substr($buf, 2);
 	}
 	$pos = index($buf, "\n");
 	while ($pos >= 0) {
 	    if ($pos eq 0) {
 		# ignore blank lines
 		$buf = substr($buf, 1);
 	    } elsif ($pos > 0) {
		my $newline = substr($buf, 0, $pos);
 		$buf = substr($buf, $pos+1);
		{
		    lock(@$readq);
		    push @$readq, $newline;
		}
 		$readq_sem->up(1);
 	    }
	    $pos = index($buf, "\n");
 	}
	$count = sysread $readfile, $inbuf, 1;
    }
}

sub waitnextline {
    my $self = shift;
    my $readq_sem = $self->{readq_sem};
    my $readq = $self->{readq};

    $readq_sem->down(1);
    lock(@$readq);
    return shift @$readq;
}

sub clearlines {
    my $self = shift;
    my $readq = $self->{readq};

    lock(@$readq);
    while (defined shift @$readq) {
    }
}

sub cmd {
    my $self = shift;
    my $cmd = shift;
    my $atprompt_sem = $self->{atprompt_sem};
    my $writefile = $self->{writefile};

    $atprompt_sem->down(1);
    print { $writefile } $cmd . "\n";
}

sub close {
    my $self = shift;
    my $writefile = $self->{writefile};
    my $readfile = $self->{readfile};
    my $read_tid = $self->{read_tid};
    my $thread = threads->object($$read_tid);

    $self->cmd("quit");
    close $writefile;
    close $readfile;
    $thread->join();
}

sub new {
    my %self : shared;
    my $atprompt_sem = Thread::Semaphore->new(0);
    my @readq : shared;
    my $readq_sem = Thread::Semaphore->new(0);
    my $read_thread;
    my $read_tid : shared;
    my $pid : shared;
    local *READFILE;
    local *WRITEFILE;
    my $a;

    $self->{atprompt_sem} = $atprompt_sem;
    $self->{readq} = \@readq;
    $self->{readq_sem} = $readq_sem;
    $self->{read_tid} = \$read_tid;
    $self->{read_pid} = \$pid;

    $pid = open2(READFILE, WRITEFILE, "$lanserv_emu")
	|| return;

    $self->{readfile} = *READFILE;
    $self->{writefile} = *WRITEFILE;

    bless $self;

    $read_thread = threads->new(\&reader, $self);
    if (! $read_thread) {
	CORE::close READFILE;
	CORE::close WRITEFILE;
	waitpid($pid, 0);
	return undef;
    }
    $read_tid = $read_thread->tid();

    $self->cmd("noecho");
    $self->waitnextline();

    return $self;
}
