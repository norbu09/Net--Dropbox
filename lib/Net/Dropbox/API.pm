package Net::Dropbox::API;

use common::sense;
use File::Basename qw(basename);
use JSON;
use Mouse;
use Net::OAuth;
use LWP::UserAgent;
use HTTP::Request::Common;
use Data::Random qw(rand_chars);
use Encode;

=head1 NAME

Net::Dropbox::API - A dropbox API interface

=head1 VERSION

Version 1.2.1

=cut

our $VERSION = '1.2';


=head1 SYNOPSIS

The Dropbox API is a OAuth based API. I try to abstract as much away as
possible so you should not need to know too much about it.
This is how it works:

    use Net::Dropbox::API;

    my $box = Net::Dropbox::API->new({key => 'KEY', secret => 'SECRET'});
    my $login_link = $box->login;  # user needs to klick this link and login
    $box->auth;                    # oauth keys get exchanged
    my $info = $box->account_info; # and here we have our account info

See the examples for a working Mojolicious web client using the Dropbox
API.

=head1 FUNCTIONS

=cut

has 'debug' => (is => 'rw', isa => 'Bool', default => 0);
has 'error' => (is => 'rw', isa => 'Str', predicate => 'has_error');
has 'key' => (is => 'rw', isa => 'Str');
has 'secret' => (is => 'rw', isa => 'Str');
has 'login_link' => (is => 'rw', isa => 'Str');
has 'callback_url' => (is => 'rw', isa => 'Str', default => 'http://localhost:3000/callback');
has 'request_token' => (is => 'rw', isa => 'Str');
has 'request_secret' => (is => 'rw', isa => 'Str');
has 'access_token' => (is => 'rw', isa => 'Str');
has 'access_secret' => (is => 'rw', isa => 'Str');
has 'context' => (is => 'rw', isa => 'Str', default => 'sandbox');


=head2 login

This sets up the initial OAuth handshake and returns the login URL. This
URL has to be clicked by the user and the the user then has to accept
the application in dropbox. 

Dropbox then redirects back to the callback URL defined with
C<$self-E<gt>callback_url>. If the user already accepted the application the
redirect may happen without the user actually clicking anywhere.

=cut

sub login {
    my $self = shift;

    my $ua = LWP::UserAgent->new;

    my $request = Net::OAuth->request("request token")->new(
        consumer_key => $self->key,
        consumer_secret => $self->secret,
        request_url => 'http://api.dropbox.com/0/oauth/request_token',
        request_method => 'POST',
        signature_method => 'HMAC-SHA1',
        timestamp => time,
        nonce => $self->nonce,
        callback => $self->callback_url,
    );

    $request->sign;
    my $res = $ua->request(GET $request->to_url);

    if ($res->is_success) {
        my $response = Net::OAuth->response('request token')->from_post_body($res->content);
        $self->request_token($response->token);
        $self->request_secret($response->token_secret);
        print "Got Request Token ", $response->token, "\n" if $self->debug;
        print "Got Request Token Secret ", $response->token_secret, "\n" if $self->debug;
        return 'http://www.dropbox.com/0/oauth/authorize?oauth_token='.$response->token.'&oauth_callback='.$self->callback_url;
    }
    else {
        $self->error($res->status_line);
        warn "Something went wrong: ".$res->status_line;
    }
}

=head2 auth

The auth method changes the initial request token into access token that we need
for subsequent access to the API. This method only has to be called once
after login.

=cut

sub auth {
    my $self = shift;

    my $ua = LWP::UserAgent->new;
    my $request = Net::OAuth->request("access token")->new(
        consumer_key => $self->key,
        consumer_secret => $self->secret,
        request_url => 'http://api.dropbox.com/0/oauth/access_token',
        request_method => 'POST',
        signature_method => 'HMAC-SHA1',
        timestamp => time,
        nonce => $self->nonce,
        callback => $self->callback_url,
        token => $self->request_token,
        token_secret => $self->request_secret,
    );

    $request->sign;
    my $res = $ua->request(GET $request->to_url);

    if ($res->is_success) {
        my $response = Net::OAuth->response('access token')->from_post_body($res->content);
        $self->access_token($response->token);
        $self->access_secret($response->token_secret);
        print "Got Access Token ", $response->token, "\n" if $self->debug;
        print "Got Access Token Secret ", $response->token_secret, "\n" if $self->debug;
    }
    else {
        $self->error($res->status_line);
        warn "Something went wrong: ".$res->status_line;
    }
}

=head2 account_info

account_info polls the users info from dropbox.

=cut

sub account_info {
    my $self = shift;

    return from_json($self->_talk('account/info'));
}

=head2 list

lists all files in the path defined.

=cut

sub list {
    my $self = shift;
    my $path = shift || '';

    return from_json($self->_talk('files/'.$self->context.'/'.$path));
}

=head2 copy

copies a folder
    copy($from, $to)

=cut

sub copy {
    my $self = shift;
    my ($from, $to) = @_;

    my $opts = 'root='.$self->context;
    return from_json($self->_talk('fileops/copy?'.$opts,
                    undef, undef, undef, undef, undef,
                    { from_path => $from, to_path => $to }));
}

=head2 move

move a folder
    move($from, $to)

=cut

sub move {
    my $self = shift;
    my ($from, $to) = @_;

    my $opts = 'root='.$self->context;
    return from_json($self->_talk('fileops/move?'.$opts,
                    undef, undef, undef, undef, undef,
                    { from_path => $from, to_path => $to }));
}

=head2 mkdir

creates a folder
    mkdir($path)

=cut

sub mkdir {
    my $self = shift;
    my ($path) = @_;

    my $opts = 'root='.$self->context;
    return from_json($self->_talk('fileops/create_folder?'.$opts,
                    undef, undef, undef, undef, undef,
                    { path => $path }));
}

=head2 delete

delete a folder
    delete($path)

=cut

sub delete {
    my $self = shift;
    my ($path) = @_;

    my $opts = 'root='.$self->context;
    return from_json($self->_talk('fileops/delete?'.$opts,
                    undef, undef, undef, undef, undef,
                    { path => $path }));
}

=head2 view

creates a cookie protected link for the user to look at.
    view($path)

=cut

sub view {
    my $self = shift;
    my ($path) = @_;

    return from_json($self->_talk('fileops/links/'.$self->context.'/'.$path));
}

=head2 metadata

creates a cookie protected link for the user to look at.
    metadata($path)

=cut

sub metadata {
    my $self = shift;
    my $path = shift || '';

    return from_json($self->_talk('metadata/'.$self->context.'/'.$path));
}

=head2 putfile

uploads a file to dropbox

=cut

sub putfile {
    my $self     = shift;
    my $file     = shift;
    my $path     = shift || '';
    my $filename = shift || basename( $file );

    return from_json(
        $self->_talk(
            'files/'.$self->context.'/'.$path,
            'POST',
            { file => [ $file ] },
            $filename, # can't decode_utf8
            'api-content',
            undef,
            { file => decode_utf8($filename) }
        )
    );

}

=head2 getfile

get a file from dropbox

=cut

sub getfile {
    my $self = shift;
    my $path = shift || '';
    my $file = shift || '';

    return $self->_talk('files/'.$self->context.'/'.$path, undef, undef, undef, 'api-content', $file);
}


=head1 INTERNAL API

=head2 _talk

_talk handles the access to the restricted resources. You should
normally not need to access this directly.

=cut

=head2 nonce

Generate a different nonce for every request.

=cut

sub nonce { join( '', rand_chars( size => 16, set => 'alphanumeric' )); }

sub _talk {
    my $self    = shift;
    my $command = shift;
    my $method  = shift || 'GET';
    my $content = shift;
    my $filename= shift;
    my $api     = shift || 'api';
    my $content_file = shift;
    my $extra_params = shift;

    my $ua = LWP::UserAgent->new;

    my %opts = (
        consumer_key => $self->key,
        consumer_secret => $self->secret,
        request_url => 'http://'.$api.'.dropbox.com/0/'.$command,
        request_method => $method,
        signature_method => 'HMAC-SHA1',
        timestamp => time,
        nonce => $self->nonce,
        #callback => $self->callback_url,
        token => $self->access_token,
        token_secret => $self->access_secret,
        extra_params => $extra_params
    );
    if($filename) {
        push @{$content->{file}},$filename;
    }

    my $request = Net::OAuth->request("protected resource")->new( %opts );

    $request->sign;

    my $res;
    if($content_file) {
        $res = $ua->get($request->to_url, ':content_file' => $content_file);
    } elsif($method =~ /get/i){
        $res = $ua->get($request->to_url);
    } else {
        $res = $ua->post($request->to_url, Content_Type => 'form-data', Content => $content );
    }

    if ($res->is_success) {
        print "Got Content ", $res->content, "\n" if $self->debug;
        return $res->content;
    }
    else {
        $self->error($res->status_line);
        warn "Something went wrong: ".$res->status_line;
    }
    return;
}

=head2 talk

=cut

=head1 AUTHOR

Lenz Gschwendtner, C<< <norbu09 at cpan.org> >>

With Bug fixes from:

Greg Knauss C<< gknauss at eod.com >>

Chris Prather C<< chris at prather.org >>

Shinichiro Aska

=head1 BUGS

Please report any bugs or feature requests to C<bug-net-dropbox-api at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-Dropbox-API>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::Dropbox::API

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-Dropbox-API>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Net-Dropbox-API>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Net-Dropbox-API>

=item * Search CPAN

L<http://search.cpan.org/dist/Net-Dropbox-API/>

=back


=head1 COPYRIGHT & LICENSE

Copyright 2010 Lenz Gschwendtner.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of Net::Dropbox
