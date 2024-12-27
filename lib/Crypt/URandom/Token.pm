package Crypt::URandom::Token;

use strict;
use warnings;
use v5.20;

use Crypt::URandom qw(urandom);
use Carp qw(croak);
use Exporter qw(import);

our @EXPORT_OK = qw(urandom_token);

our $VERION = "0.001_001";

=head1 NAME

Crypt::URandom::Token - Generate tokens from cryptographically secure
pseudorandom bytes

=head1 SYNOPSIS

  # Function usage:

  use Crypt::URandom::Token qw(urandom_token);
  my $token = urandom_token(); # generates a 44-character alphanumeric token

  # Object usage:

  use Crypt::URandom::Token;
  my $obj = Crypt::URandom::Token->new(
      length   => 44,
      alphabet => [ A..Z, a..z, 0..9 ],
  );
  my $token = $obj->get;

=head1 DESCRIPTION

This module provides a secure way to generate a random token for tokens and
similar using L<Crypt::URandom> as a source of random bits.

By default, it generates an alphanumeric token with more than 256 bits of
entropy, which should be sufficient for most purposes as of 2025.

=head1 FUNCTIONS

=head2 urandom_token($length = 44, $alphabet = [ A..Z, a..z, 0..9 ]);

Returns a cryptographically secure random token suitable for token.

If C<$length> is not provided, it defaults to 44.

If C<$alphabet> is not provided, it defaults to uppercase letters, lowercase
letters, and digits. You can provide either a token of characters or an
arrayref.

=head1 METHODS

=head2 new

Creates a new token generator object. Accepts a hash or hashref with these
paramters:

=over 4

=item * C<length> - desired token length (defaults to 44)

=item * C<alphabet> - the set of characters to use. Can be a token (split into individual chars) or an array reference. Defaults to [ A..Z, a..z, 0..9 ]

=back

=head2 get

Generates and returns a random token as a token, using the object's
attributes for length and alphabet.

=head1 AUTHOR

Stig Palmquist <stig@stig.io>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut

sub new {
  my ($class, @args) = @_;
  if (@args == 1 && ref $args[0] eq 'HASH') {
    @args = %{ $args[0] };
  }
  my %args = @args;
  return bless \%args, $class;
}

sub get {
  my $self = shift;
  return urandom_token($self->{length}, $self->{alphabet});
}

sub _alphabet {
  my $in = shift;

  my @alphabet;
  if ( ref $in eq 'ARRAY' ) {
    @alphabet = @$in;
  } elsif (defined $in && !ref $in) {
    @alphabet = split("", ($in // ""));
  } else {
    @alphabet = ("A" .. "Z", "a" .. "z", "0" .. "9");
  }

  unless (@alphabet >= 2 && @alphabet <= 256) {
    croak "alphabet size must be between 2 and 256 elements";
  }

  return @alphabet;
}

sub urandom_token {
  my $length   = shift || 44;
  my @alphabet = _alphabet(shift);

  my $bias_lim = 256 % @alphabet;

  my (@bytes, @token);
  while (@token < $length) {
    @bytes = split "", urandom(64) unless @bytes;
    my $num = ord(shift @bytes);
    next if $num < $bias_lim;
    push @token, $alphabet[$num % @alphabet];
  }
  return join "", @token;
}

1;
