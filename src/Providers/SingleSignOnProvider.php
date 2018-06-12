<?php

namespace Donews\Stargame\Providers;

use Illuminate\Support\ServiceProvider;
use Donews\Stargame\Services\SSOSDK;

class SingleSignOnProvider extends ServiceProvider
{
    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = true;

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton(SSOSDK::class, function ($app) {
            return new SSOSDK($app['config']['services.xysso']);
        });
    }
    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides()
    {
        return [SSOSDK::class];
    }
}
