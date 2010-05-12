package Net::Dropbox;

use common::sense;
use JSON;
use Mouse;
use Net::OAuth;
use LWP::UserAgent;
use HTTP::Request::Common;
use Data::Random qw(rand_chars);

=head1 NAME

Net::Dropbox - The great new Net::Dropbox!

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';


=head1 SYNOPSIS

Quick summary of what the module does.

Perhaps a little code snippet.

    use Net::Dropbox;

    my $foo = Net::Dropbox->new();
    ...

=head1 EXPORT

A list of functions that can be exported.  You can delete this section
if you don't export anything, such as for a purely object-oriented module.

=head1 FUNCTIONS

=cut

has 'debug' => (is => 'rw', isa => 'Bool', default => 0);
has 'error' => (is => 'rw', isa => 'Str', predicate => 'has_error');
has 'key' => (is => 'rw', isa => 'Str');
has 'secret' => (is => 'rw', isa => 'Str');
has 'nonce' => (is => 'ro', isa => 'Str', default => join( '', rand_chars( size => 16, set => 'alphanumeric' ) ));
has 'login_link' => (is => 'rw', isa => 'Str');
has 'callback_url' => (is => 'rw', isa => 'Str', default => 'http://localhost:3000/callback');
has 'request_token' => (is => 'rw', isa => 'Str');
has 'request_secret' => (is => 'rw', isa => 'Str');
has 'access_token' => (is => 'rw', isa => 'Str');
has 'access_secret' => (is => 'rw', isa => 'Str');

=head2 login
This sets up the initial OAuth handshake and returns the login URL. This
URL has to be clicked by the user and the the user then has to accept
the application in dropbox. 
Dropbox then redirects back to the callback URL defined with
$self->callback_url. If the user already accepted the application the
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
        return 'http://api.dropbox.com/0/oauth/authorize?oauth_token='.$response->token.'&oauth_callback='.$self->callback_url;
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

=head2 list_files
lists all files un the path defined.
Paths starting with 'dropbox/' refer to the users dropbox and paths
starting with 'sandbox/' refer to the sandbox directory the user asigned
to the application.
=cut
sub list_files {
    my $self = shift;
    my $path = shift;

    return from_json($self->_talk('files/'.$path));
}



=head1 INTERNAL API
=head2 _talk
_talk handles the access to the restricted resources. You should
normally not need to access this directly.
=cut

sub _talk {
    my $self = shift;
    my $command = shift;
    my $method = shift || 'GET';

    my $ua = LWP::UserAgent->new;
    my $request = Net::OAuth->request("protected resource")->new(
        consumer_key => $self->key,
        consumer_secret => $self->secret,
        request_url => 'http://api.dropbox.com/0/'.$command,
        request_method => $method,
        signature_method => 'HMAC-SHA1',
        timestamp => time,
        nonce => $self->nonce,
        #callback => $self->callback_url,
        token => $self->access_token,
        token_secret => $self->access_secret,
    );

    $request->sign;

    my $res;
    if($method =~ /get/i){
        $res = $ua->get($request->to_url);
    } else {
        $res = $ua->post($request->to_url);
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

=head1 BUGS

Please report any bugs or feature requests to C<bug-net-dropbox at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-Dropbox>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::Dropbox


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-Dropbox>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Net-Dropbox>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Net-Dropbox>

=item * Search CPAN

L<http://search.cpan.org/dist/Net-Dropbox/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 COPYRIGHT & LICENSE

Copyright 2010 Lenz Gschwendtner.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of Net::Dropbox
