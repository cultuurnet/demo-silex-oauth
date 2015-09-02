<?php
use CultuurNet\Auth\ConsumerCredentials;
use CultuurNet\SymfonySecurityOAuth\OAuthAuthenticationProvider;
use CultuurNet\SymfonySecurityOAuth\OAuthListener;
use CultuurNet\UitidCredentials\UitidCredentialsFetcher;
use DerAlex\Silex\YamlConfigServiceProvider;
use Symfony\Component\HttpFoundation\Request;

require_once __DIR__.'/../vendor/autoload.php';

$app = new Silex\Application();

$app->register(new YamlConfigServiceProvider(__DIR__ . '/../config.yml'));


$app['oauth.fetcher'] = $app->share(function ($app) {
  $baseUrl = $app['config']['oauth.base_url'];
  $consumerkey = $app['config']['oauth.consumer.key'];
  $consumersecret = $app['config']['oauth.consumer.secret'];

  $consumerCredentials = new ConsumerCredentials($consumerkey, $consumersecret);

  return new UitidCredentialsFetcher($baseUrl, $consumerCredentials);
});

$app['security.authentication_listener.factory.oauth'] = $app->protect(function ($name, $options) use ($app) {
  // define the authentication provider object
  $app['security.authentication_provider.'.$name.'.oauth'] = $app->share(function () use ($app) {
    return new OAuthAuthenticationProvider($app['security.user_provider.default'], __DIR__.'/security_cache', $app['oauth.fetcher']);
  });

  // define the authentication listener object
  $app['security.authentication_listener.'.$name.'.oauth'] = $app->share(function () use ($app) {
    // use 'security' instead of 'security.token_storage' on Symfony <2.6
    return new OAuthListener($app['security.token_storage'], $app['security.authentication_manager']);
  });

  return array(
    // the authentication provider id
    'security.authentication_provider.'.$name.'.oauth',
    // the authentication listener id
    'security.authentication_listener.'.$name.'.oauth',
    // the entry point id
    null,
    // the position of the listener in the stack
    'pre_auth'
  );
});

$app->register(new Silex\Provider\SecurityServiceProvider(), array(
  'security.firewalls' => array(
    'default' => array(
      'oauth' => true,
    ),
  ),
));

$app['oauth.request_listener'] = $app->share(function() {
  return new \CultuurNet\SymfonySecurityOAuth\OAuthRequestListener();
});

$app['dispatcher']->addListener('kernel.request', array($app['oauth.request_listener'], 'onEarlyKernelRequest'), 255);

$app->run();