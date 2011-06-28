use inc::Module::Install;

name     'Net-Dropbox-API';
all_from 'lib/Net/Dropbox/API.pm';
author   q{Lenz Gschwendtner <norbu09@cpan.org>};
license  'perl';

build_requires 'Test::More';

requires 'URI';
requires 'JSON';
requires 'Mouse';
requires 'Encode';
requires 'Net::OAuth';
requires 'Data::Random';
requires 'common::sense';
requires 'File::Basename';
requires 'LWP::UserAgent';
requires 'HTTP::Request::Common';

auto_install;

repository 'https://github.com/norbu09/Net--Dropbox';

WriteAll;

