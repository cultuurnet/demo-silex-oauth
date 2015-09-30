<?php
use CultuurNet\SilexServiceProviderOAuth\OAuthServiceProvider;
use CultuurNet\SymfonySecurityOAuth\Model\Provider\TokenProviderInterface;
use CultuurNet\SymfonySecurityOAuthRedis\NonceProvider;
use CultuurNet\SymfonySecurityOAuthRedis\TokenProviderCache;
use DerAlex\Silex\YamlConfigServiceProvider;
use Silex\Application;

require_once __DIR__.'/../vendor/autoload.php';

$app = new Silex\Application();

$app['debug'] = true;

if (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
    $_SERVER['HTTP_AUTHORIZATION'] = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
}

$app->register(new YamlConfigServiceProvider(__DIR__ . '/../config.yml'));

$app->register(new OAuthServiceProvider(), array(
    'oauth.fetcher.base_url' => $app['config']['oauth']['base_url'],
    'oauth.fetcher.consumer' => $app['config']['oauth']['consumer'],
));

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

$app->extend(
    'oauth.model.provider.token_provider',
    function (TokenProviderInterface $tokenProvider, Application $app) {
        return new TokenProviderCache($tokenProvider, $app['predis.client']);
    }
);

$app->register(new Silex\Provider\SecurityServiceProvider(), array(
  'security.firewalls' => array(
    'default' => array(
      'oauth' => true,
    ),
  ),
));

$app->get('/test', function (Application $app) { return new \Symfony\Component\HttpFoundation\Response();} );

$app->get('/hello/{name}', function ($name) use ($app) {
    return 'Hello '.$app->escape($name);
});

$app->run();
