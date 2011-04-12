use inc::Module::Install;

name     'Net-Dropbox-API';
all_from 'lib/Net/Dropbox/API.pm';
author   q{Lenz Gschwendtner <norbu09@cpan.org>};
license  'perl';

build_requires 'Test::More';

requires 'JSON';
requires 'Mouse';
requires 'Net::OAuth';
requires 'common::sense';
requires 'LWP::UserAgent';
requires 'HTTP::Request::Common';
requires 'Data::Random';

auto_install;

repository 'https://github.com/norbu09/Net--Dropbox';

WriteAll;

