<?php

// Login Route (Shibboleth and Local)
Route::get('/login', 'StudentAffairsUwm\Shibboleth\Controllers\ShibbolethController@create');
// Logout Route (Shibboleth and Local)
Route::get('/logout', 'StudentAffairsUwm\Shibboleth\Controllers\ShibbolethController@destroy');
// Shibboleth IdP Callback
Route::get('/idp', 'StudentAffairsUwm\Shibboleth\Controllers\ShibbolethController@idpAuthorize');

// Login Route (Local)
Route::get('/local', 'StudentAffairsUwm\Shibboleth\Controllers\ShibbolethController@localCreate');
// Login Callback (Local)
Route::post('/local', 'StudentAffairsUwm\Shibboleth\Controllers\ShibbolethController@localAuthorize');
