use strict;
use warnings;
use Digest::SHA qw(sha256_hex);

my $file1 = "msg.in";
my $file2 = "msg.dec";
my $file3 = "msg.enc";
my $digest4 = '';

my $filesize = 500 + int(rand(1000));

open my $wr, '>', "msg.in" or die "Cannot open 'msg.in' for writing";
binmode($wr);

for(1..$filesize) {
  unless($_ % 91) { print WR chr(0) }
  print $wr chr(int(rand(256)));
}

for(1..6) { print WR chr(0) }

close $wr or die "Cannot close 'msg.in' after writing";

my($enc, $dec);

if(-e "encrypt.exe")        { $enc = "encrypt.exe" }
elsif(-e "encrypt") { $enc = "encrypt" }
else { die "Cannot find the encrypt executable" }


if(-e "decrypt.exe")        { $dec = "decrypt.exe" }
elsif(-e "decrypt") { $dec = "decrypt" }
else { die "Cannot find the decrypt executable" }

if($^O =~ /MSWin32/i) {
  $enc = ".\\" . $enc;
  $dec = ".\\" . $dec;
}
else {
  $enc = "./" . $enc;
  $dec = "./" . $dec;
}

for(1..100) {
  system $enc;
  system $dec;
  my $digest1 = dig($file1);
  my $digest2 = dig($file2);
  my $digest3 = dig($file3);

  if($digest1 eq $digest2 && $digest3 ne $digest2 && $digest3 ne $digest4) {
    print "ok $_\n";
  }
  else {
    die "Failed for $_:\n$digest1\n$digest2\n$digest3\n $digest4\n";
  }

  $digest4 = $digest3;
}

sub dig {
  open(my $RD1, $_[0]) or warn "Can't open $_[0]: $!";
  binmode($RD1);
  my $sha256 = Digest::SHA->new(256);
  $sha256->addfile($RD1);
  my $digest = $sha256->hexdigest;
  close($RD1) or warn "Can't close $_[0]: $!";
  return $digest;
}
