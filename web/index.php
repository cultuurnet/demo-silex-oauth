<?php
use CultuurNet\Auth\ConsumerCredentials;
use CultuurNet\SymfonySecurityOAuth\Security\OAuthAuthenticationProvider;
use CultuurNet\SymfonySecurityOAuth\Security\OAuthListener;
use CultuurNet\SymfonySecurityOAuth\Service\OAuthServerService;
use CultuurNet\SymfonySecurityOAuth\Service\Signature\OAuthHmacSha1Signature;
use CultuurNet\SymfonySecurityOAuthRedis\NonceProvider;
use CultuurNet\SymfonySecurityOAuthUitid\ConsumerProvider;
use CultuurNet\SymfonySecurityOAuthUitid\TokenProvider;
use CultuurNet\UitidCredentials\UitidCredentialsFetcher;
use DerAlex\Silex\YamlConfigServiceProvider;
use Silex\Application;

require_once __DIR__.'/../vendor/autoload.php';

$app = new Silex\Application();

$app['debug'] = true;

if (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
    $_SERVER['HTTP_AUTHORIZATION'] = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
}

$app->register(new YamlConfigServiceProvider(__DIR__ . '/../config.yml'));

$app['oauth.fetcher'] = $app->share(function () use ($app) {
  $baseUrl = $app['config']['oauth']['base_url'];
  $consumerkey = $app['config']['oauth']['consumer']['key'];
  $consumersecret = $app['config']['oauth']['consumer']['secret'];

  $consumerCredentials = new ConsumerCredentials($consumerkey, $consumersecret);

  return new UitidCredentialsFetcher($baseUrl, $consumerCredentials);
});

$app['oauth.model.provider.consumer_provider'] = $app->share(function ($app) {
    return new ConsumerProvider($app['oauth.fetcher']);
});

$app['oauth.model.provider.token_provider'] = $app->share(function ($app) {
    return new TokenProvider($app['oauth.fetcher']);
});

$app['predis.client'] = $app->share(function ($app) {
    $redisURI = isset($app['config']['redis']['uri']) ?
        $app['config']['redis']['uri'] : 'tcp://127.0.0.1:6379';

    return new Predis\Client($redisURI);
});

$app['oauth.model.provider.nonce_provider'] = $app->share(function (Application $app) {
    return new NonceProvider(
        $app['predis.client']
    );
});

$app['oauth.service.oauth_server_service'] = $app->share(function () use ($app) {
    $consumerProvider = $app['oauth.model.provider.consumer_provider'];
    $tokenProvider = $app['oauth.model.provider.token_provider'];
    $nonceProvider = $app['oauth.model.provider.nonce_provider'];
    $serverService =  new OAuthServerService($consumerProvider, $tokenProvider, $nonceProvider);
    $hmacsha1Service = new OAuthHmacSha1Signature();
    $serverService->addSignatureService($hmacsha1Service);

    return $serverService;
});

$app['security.authentication_listener.factory.oauth'] = $app->protect(function ($name, $options) use ($app) {
  // define the authentication provider object
  $app['security.authentication_provider.'.$name.'.oauth'] = $app->share(function () use ($app) {
    return new OAuthAuthenticationProvider(
        $app['security.user_provider.default'],
        $app['oauth.service.oauth_server_service'] //__DIR__.'/security_cache',
    );
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
  return new \CultuurNet\SymfonySecurityOAuth\EventListener\OAuthRequestListener();
});

$app['dispatcher']->addListener('kernel.request', array($app['oauth.request_listener'], 'onEarlyKernelRequest'), 255);

$app->get('/test', function (Application $app) { return new \Symfony\Component\HttpFoundation\Response();} );

$app->get('/hello/{name}', function ($name) use ($app) {
    return 'Hello '.$app->escape($name);
});

$app->run();
