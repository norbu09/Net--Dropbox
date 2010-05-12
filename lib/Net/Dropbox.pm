package Net::Dropbox;

use common::sense;
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

=head2 login

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

sub login_url {
    my $self = shift;
    #$Net::OAuth::PROTOCOL_VERSION = Net::OAuth::PROTOCOL_VERSION_1_0A;
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
        #extra_params => {
        #    apple => 'banana',
        #    kiwi => 'pear',
        #}
    );

    $request->sign;

    my $res = $ua->request(GET $request->to_url); # Post message to the Service Provider

    if ($res->is_success) {
        my $response = Net::OAuth->response('request token')->from_post_body($res->content);
        $self->request_token($response->token);
        $self->request_secret($response->token_secret);
        print "Got Request Token ", $response->token, "\n" if $self->debug;
        print "Got Request Token Secret ", $response->token_secret, "\n" if $self->debug;
        return 'http://api.dropbox.com/0/oauth/authorize?oauth_token='.$response->token.'&oauth_callback='.$self->callback_url;
    }
    else {
        warn "Something went wrong: ".$res->status_line;
    }
}

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
        #extra_params => {
        #    apple => 'banana',
        #    kiwi => 'pear',
        #}
    );

    $request->sign;

    my $res = $ua->request(GET $request->to_url); # Post message to the Service Provider

    if ($res->is_success) {
        my $response = Net::OAuth->response('access token')->from_post_body($res->content);
        $self->access_token($response->token);
        $self->access_secret($response->token_secret);
        print "Got Access Token ", $response->token, "\n" if $self->debug;
        print "Got Access Token Secret ", $response->token_secret, "\n" if $self->debug;
    }
    else {
        warn "Something went wrong: ".$res->status_line;
    }
}

sub account_info {
    my $self = shift;

    return $self->_talk('account/info');
}

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
        #extra_params => {
        #    apple => 'banana',
        #    kiwi => 'pear',
        #}
    );

    $request->sign;

    my $res;
    if($method =~ /get/i){
        $res = $ua->get($request->to_url); # Post message to the Service Provider
    } else {
        $res = $ua->post($request->to_url); # Post message to the Service Provider
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

sub talk {
}

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
