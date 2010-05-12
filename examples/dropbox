#!/usr/bin/env perl

use FindBin;
use Mojolicious::Lite;
use lib "$FindBin::Bin/../lib";
use Net::Dropbox::API;
use Data::Dumper;

my $box = Net::Dropbox->new({key => 'KEY', secret=>'SECRET'});
my $pending;

get '/' => sub  {
    my $self = shift;
    $self->stash->{login} = $box->login;
    $pending->{$box->request_token} = $box->request_secret;
} => 'index';

get '/callback?:stuff' => sub  {
    my $self = shift;
    app->log->debug($self->param('oauth_token'));
    my $secret = delete $pending->{$self->param('oauth_token')};
    $box->auth({request_token => $self->param('oauth_token'), request_secret => $secret});

    $box->context('dropbox');
    my $response = $box->list;
    app->log->debug(Dumper($response));
    $self->render_text(Dumper($response), layout => 'default');
};

app->start;
__DATA__

@@ index.html.ep
% layout 'default';
<a href="<%= $login %>">login to dropbox</a>

@@ layouts/default.html.ep
<!doctype html><html>
    <head><title>Funky!</title></head>
    <body>
      <pre>
      <%== content %>
      </pre>
    </body>
</html>
