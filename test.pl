use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Digest::SHA qw(sha256_hex sha1_hex);

my $file1 = "msg.in";
my $file2 = "msg.dec";
my $file3 = "msg.enc";
my $digest4 = '';

for(1..100) {
  system 'encrypt.exe';
  system 'decrypt.exe';
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
