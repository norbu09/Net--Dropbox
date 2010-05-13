#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'Net::Dropbox::API' );
}

diag( "Testing Net::Dropbox::API $Net::Dropbox::API::VERSION, Perl $], $^X" );
