#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'Net::Dropbox' );
}

diag( "Testing Net::Dropbox $Net::Dropbox::VERSION, Perl $], $^X" );
