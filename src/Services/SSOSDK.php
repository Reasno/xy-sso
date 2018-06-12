<?php

namespace Donews\Stargame\Services;

/**
 * 后台用户中心单点登录SDK
 *
 * @version Version 1.2
 *
 */

class SSOSDK
{

    protected $appId;

    protected $appKey;

    protected $ssoUrl = 'http://admin-sso.stargame.com';

    protected $apiAuthVer = 'PWRDAA0.1';

    protected $ssoCookie = 'sso_login';

    protected $domain = '';

    protected $errorMsg = '';

    public function __construct($config)
    {
        $this->appId = (int)$config['appId'];
        $this->appKey = (string)$config['appKey'];
        if ($config['domain']) {
            $this->domain = $config['domain'];
        } else {
            if (!empty($_SERVER['HTTP_HOST'])) {
                $tmp = explode('.', $_SERVER['HTTP_HOST']);
                $count = count($tmp);
                if ($count>=2) {
                    $this->domain = $tmp[$count-2] . '.' . $tmp[$count-1];
                }
            }
        }
    }

    /**
     * 获取错误信息
     * @return string
     */
    public function getErrorMsg()
    {
        return $this->errorMsg;
    }

    /**
     * 生成request_token签名
     * @param $t
     * @return string
     */
    protected function requestSign($t)
    {
        return md5($this->appId . substr($this->appKey, 0, 20) . $t);
    }

    /**
     * 生成登录url
     * @param null $callback
     * @param null $state
     * @return string
     */
    public function getLoginUrl($callback = null, $state = null)
    {
        $t = time();
        $sign = $this->requestSign($t);
        $requestToken = $this->urlSafeBase64Encode($sign . '|' . $t);
        $url = $this->ssoUrl . '/auth/login?app_id=' . $this->appId . '&request_token=' . $requestToken;
        if ($callback) {
            $url .= '&callback=' . rawurlencode($callback);
        }
        if ($state) {
            $url .= '&state=' . rawurlencode($state);
        }
        return $url;
    }

    /**
     * 注销用户，跳到退出url
     * @param null $to
     */
    public function logout($to = null)
    {
        setcookie($this->ssoCookie, '', -1, '/', $this->domain, false, true);
        header('Location: ' . $this->getLogoutUrl($to));
    }

    public function delCookie()
    {
        setcookie($this->ssoCookie, '', -1, '/', $this->domain, false, true);
    }

    /**
     * 获取登出url
     * @param null $to
     * @return string
     */
    public function getLogoutUrl($to = null)
    {
        $url = $this->ssoUrl . '/auth/logout';
        if ($to) {
            $url .= '?to=' . rawurlencode($to);
        }
        return $url;
    }

    /**
     * 根据apiName请求接口，返回结果集
     * @param $apiName
     * @param array $params
     * @param string $token
     * @return bool|mixed
     */
    public function request($apiName, $params = array(), $token = '')
    {
        $expires = time() + 600;
        $sign = $this->makeSign($params, $token, $this->appKey, $expires);
        $headerParams = array(
            'app_id' => $this->appId,
            'app_token' => $token,
            'app_sign' => $sign,
            'app_expires' => $expires
        );
        $authorization = $this->apiAuthVer . ' ' .http_build_query($headerParams);
        $headerArr[] = 'Authorization: ' . $authorization;
        $url = $this->ssoUrl . '/api/' . $apiName;
        $result = $this->curlPost($url, $params, array(CURLOPT_HTTPHEADER => $headerArr));
        $result = @json_decode($result, true);
        if (!$result || !isset($result['code'])) {
            return false;
        }
        return $result;
    }

    /**
     * 检测是否登录
     * @param null $token
     * @return bool
     */
    public function checkLogin($token = null)
    {
        if (!$token) {
            $token = isset($_COOKIE[$this->ssoCookie]) ? $_COOKIE[$this->ssoCookie] : null;
        }
        if (!$token) {
            $this->errorMsg = 'no token';
            return false;
        }
        $result = $this->request('getUserByCookie', array(), $token);
        if (!$this->checkResult($result, array('id', 'username', 'email'))) {
            return false;
        }
        $user = $result['result'];
        return $user;
    }

    /**
     * 获取当前登录用户信息
     * @param $accessToken
     * @param bool $login
     * @return bool
     */
    public function getUserByAccessToken($accessToken, $login = true)
    {
        if (!$accessToken) {
            $this->errorMsg = 'no token';
            return false;
        }
        $params = array(
            'access_token' => $accessToken,
        );
        $result = $this->request('getUserByAccessToken', $params);
        if (!$this->checkResult($result, array('id', 'username', 'email', 'token'))) {
            return false;
        }
        $user = $result['result'];
        if ($login) {
            setcookie($this->ssoCookie, $user['token'], $user['expire'], '/', $this->domain, false, true);
        }
        return $user;
    }

    /**
     * 获取当前登录用户信息（角色和等级）
     * @param $accessToken
     * @param bool $login
     * @return bool
     */
    public function getUserLevelByAccessToken($accessToken, $login = true)
    {
        if (!$accessToken) {
            $this->errorMsg = 'no token';
            return false;
        }
        $params = array(
            'access_token' => $accessToken,
        );
        $result = $this->request('getUserLevelByAccessToken', $params);
        if (!$this->checkResult($result, array('id', 'username', 'email', 'token', 'roles', 'site_levels'))) {
            return false;
        }
        $user = $result['result'];
        if ($login) {
            setcookie($this->ssoCookie, $user['token'], $user['expire'], '/', $this->domain, false, true);
        }
        return $user;
    }

    /**
     * 根据邮箱获取某个用户的信息
     * @param $email
     * @return bool
     */
    public function getUserByEmail($email)
    {
        $params = array(
            'email' => $email,
        );
        $result = $this->request('getUserByEmail', $params);
        if (!$this->checkResult($result, array('id', 'username', 'email'))) {
            return false;
        }
        $user = $result['result'];
        return $user;
    }

    /**
     * 根据用户id获取某个用户的信息（角色和等级）
     * @param $email
     * @return bool
     */
    public function getUserLevelByUserId($user_id)
    {
        $params = array(
            'user_id' => $user_id,
        );
        $result = $this->request('getUserLevelByUserId', $params);
        if (!$this->checkResult($result, array('id', 'username', 'email', 'roles', 'site_levels'))) {
            return false;
        }
        $user = $result['result'];
        return $user;
    }

    /**
     * 获取当前平台所有用户列表
     * @return mixed
     */
    public function getUserList()
    {
        $result = $this->request('getUserList');
        $user = $result['result'];
        return $user;
    }

    /**
     * 获取当前平台所有用户列表(包括角色和等级)
     * @return mixed
     */
    public function getUserLevelList()
    {
        $result = $this->request('getUserLevelList');
        $user = $result['result'];
        return $user;
    }

    /**
     * 用户登录
     * @param $email
     * @param $password
     * @param bool $remember
     * @param bool $setCookie
     * @return bool
     */
    public function login($email, $password, $remember = false, $setCookie = true)
    {
        $params = array(
            'email' => $email,
            'password' => $password,
        );
        if ($remember) {
            $params['remember'] = 1;
        }
        $result = $this->request('login', $params);
        if (!$this->checkResult($result, array('id', 'username', 'email', 'token'))) {
            return false;
        }
        $user = $result['result'];
        if ($setCookie) {
            setcookie($this->ssoCookie, $user['token'], isset($user['expire'])
                ? $user['expire'] : 0, '/', $this->domain, false, true);
        }
        return $user;
    }

    /**
     * 根据appId获取平台信息
     * @param $id
     * @return bool
     */
    public function getApp($id)
    {
        $params = array(
            'app_id' => $id,
        );
        $result = $this->request('getApp', $params);
        if (!$this->checkResult($result, array('id', 'name', 'domain', 'home'))) {
            return false;
        }
        $app = $result['result'];
        return $app;
    }

    /**
     * 修改当前登录用户手机号
     * @param $mobile
     * @param null $token
     * @return bool
     */
    public function setMobile($mobile, $token = null)
    {
        if (!$token) {
            $token = isset($_COOKIE[$this->ssoCookie]) ? $_COOKIE[$this->ssoCookie] : null;
        }
        if (!$token) {
            $this->errorMsg = 'no token';
            return false;
        }
        $result = $this->request('setMobile', array('mobile' => $mobile), $token);
        if (!$this->checkResult($result, array('id', 'username', 'email'))) {
            return false;
        }
        $user = $result['result'];
        return $user;
    }

    /**
     * 检测结果集字段
     * @param $result
     * @param null $fields
     * @return bool
     */
    protected function checkResult($result, $fields = null)
    {
        if (!$result || $result['code'] != 0 || !isset($result['result'])) {
            if (!$this->errorMsg) {
                $this->errorMsg = $result ? $result['message'] : 'no response';
            }
            return false;
        }
        if ($fields && is_array($fields)) {
            $data = $result['result'];
            foreach ($fields as $k) {
                if (empty($data[$k])) {
                    $this->errorMsg = 'bad result';
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * 生成签名
     * @param $params
     * @param $appToken
     * @param $appKey
     * @param $appExpires
     * @return string
     */
    public function makeSign($params, $appToken, $appKey, $appExpires)
    {
        return md5(
            $this->concat(
                $this->makeQueryString($params),
                $appToken,
                $appKey,
                $appExpires
            )
        );
    }

    /**
     * 拼接字符串
     * @return string
     */
    public function concat()
    {
        $result = '';
        foreach (func_get_args() as $val) {
            $result .= $val;
        }
        return $result;
    }

    /**
     * 生成http字符串
     * @param $array
     * @return string
     */
    public function makeQueryString($array)
    {
        return http_build_query($array);
    }

    /**
     * 数组排序
     * @param $array
     * @return mixed
     */
    public function sortNaturally($array)
    {
        ksort($array, SORT_STRING | SORT_NATURAL | SORT_FLAG_CASE); // 5.4以上
        return $array;
    }

    /**
     * url base64编码
     * @param $str
     * @return string
     */
    public function urlSafeBase64Encode($str)
    {
        return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
    }

    /**
     * url base64解码
     * @param $str
     * @return string
     */
    public function urlSafeBase64Decode($str)
    {
        return base64_decode(str_pad(strtr($str, '-_', '+/'), strlen($str) % 4, '=', STR_PAD_RIGHT));
    }

    /**
     * curl发送post请求
     * @param $url
     * @param array $param
     * @param array $option
     * @return bool|mixed
     */
    public function curlPost($url, $param = array(), $option = array())
    {
        if (empty($url)) {
            return false;
        }
        $param_array = array();
        if (is_string($param)) {
            parse_str($param, $param_array);
        } else {
            $param_array = $param;
        }

        $defaults = array(
            CURLOPT_POST => 1,
            CURLOPT_HEADER => 0,
            CURLOPT_URL => $url,
            CURLOPT_FRESH_CONNECT => 1,
            CURLOPT_RETURNTRANSFER => 1,
            CURLOPT_FORBID_REUSE => 1,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_POSTFIELDS => http_build_query($param_array),
        );

        $ch = curl_init();
        $option = $option + $defaults;
        curl_setopt_array($ch, $option);
        $result = curl_exec($ch);
        if (!$result) {
            $this->errorMsg = curl_error($ch);
            curl_close($ch);
            return false;
        }
        curl_close($ch);
        return $result;
    }
}
