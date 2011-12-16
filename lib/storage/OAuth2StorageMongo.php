<?php

defined('SYSPATH') or die('No direct script access.');

require_once __DIR__ . '/../OAuth2.php';
require_once __DIR__ . '/../IOAuth2Storage.php';
require_once __DIR__ . '/../IOAuth2GrantCode.php';
require_once __DIR__ . '/../IOAuth2GrantUser.php';
require_once __DIR__ . '/../IOAuth2RefreshTokens.php';

/**
 * Mongo storage engine for the OAuth2 Library.
 */
class OAuth2StorageMongo implements IOAuth2GrantUser, IOAuth2GrantCode, IOAuth2RefreshTokens {
    /**
     * Change this to something unique for your system
     * @var string
     */
    const SALT = 'CHANGE ME!!!!';
    const COLLECTION_CLIENTS = 'oauth.clients';
    const COLLECTION_CODES = 'oauth.codes';
    const COLLECTION_TOKENS = 'oauth.access_tokens';
    const COLLECTION_REFRESH = 'oauth.refresh_tokens';

    /**
     * @var Mongo
     */
    private $db;

    /**
     * Implements OAuth2::__construct().
     */
    public function __construct($db) {
        $this->db = $db;
    }

    /**
     * Release DB connection during destruct.
     */
    function __destruct() {
        $this->db = NULL; // Release db connection
    }

    /**
     * Handle Mongo exceptional cases.
     */
    private function handleException($e) {
        throw $e;
    }

    /**
     * Little helper function to add a new client to the database.
     *
     * @param $client_id
     *   Client identifier to be stored.
     * @param $client_secret
     *   Client secret to be stored.
     * @param $redirect_uri
     *   Redirect URI to be stored.
     */
    public function addClient($client_id, $client_secret, $redirect_uri) {
        try {
            $this->db->{self::COLLECTION_CLIENTS}->insert(array(
                "_id" => $client_id,
                "secret" => $this->hash($client_secret, $client_id),
                "redirect_uri" => $redirect_uri
            ));
        } catch (MongoException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Implements IOAuth2Storage::checkClientCredentials().
     *
     */
    public function checkClientCredentials($client_id, $client_secret = NULL) {
        try {
            $client = $this->db->{self::COLLECTION_CLIENTS}->findOne(array(
                "_id" => $client_id
                    ));

            if ($client_secret === NULL) {
                return $client !== NULL;
            }

            return $client['secret'] == $this->hash($client_secret, $client_id);
        } catch (MongoException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Implements IOAuth2Storage::getRedirectUri().
     */
    public function getClientDetails($client_id) {
        try {
            $result = $this->db->{self::COLLECTION_CLIENTS}->findOne(
                    array("_id" => $client_id), array('redirect_uri')
            );
            return @array('redirect_uri' => $result['redirect_uri']);
        } catch (MongoException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Implements IOAuth2Storage::getAccessToken().
     */
    public function getAccessToken($oauth_token) {
        return $this->getToken($oauth_token, FALSE);
    }

    /**
     * Implements IOAuth2Storage::setAccessToken().
     */
    public function setAccessToken($oauth_token, $client_id, $user_id, $expires, $scope = NULL) {
        $this->setToken($oauth_token, $client_id, $user_id, $expires, $scope, FALSE);
    }

    /**
     * @see IOAuth2Storage::getRefreshToken()
     */
    public function getRefreshToken($refresh_token) {
        return $this->getToken($refresh_token, TRUE);
    }

    /**
     * @see IOAuth2Storage::setRefreshToken()
     */
    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = NULL) {
        return $this->setToken($refresh_token, $client_id, $user_id, $expires, $scope, TRUE);
    }

    /**
     * @see IOAuth2Storage::unsetRefreshToken()
     */
    public function unsetRefreshToken($refresh_token) {
        try {
            $this->db->{self::COLLECTION_REFRESH}->remove(array('_id' => $refresh_token));
        } catch (MongoException $e) {
            $this->handleException($e);
        }
    }

    /**
     * @see IOAuth2RefreshTokens::unsetExpiredRefreshTokens()
     */
    public function unsetExpiredRefreshTokens($older_than) {
        $this->removeExpired($older_than, TRUE);
    }

    /**
     * Implements IOAuth2GrantUser::checkUserCredentials()
     */
    public function checkUserCredentials($client_id, $username, $password) {
        
        // Psuedo Code:
        //
        //  if(user_is_valid(username, password)):
        //      return {client_id: $client_id, user_id: $username}
        //  else
        //      return FALSE;
        
        return FALSE;
    }

    /**
     * Implements IOAuth2Storage::getAuthCode().
     */
    public function getAuthCode($code) {
        try {
            $code = $this->db->{self::COLLECTION_CODES}->findOne(array('_id' => $code));
            return $code;
        } catch (MongoException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Implements IOAuth2Storage::setAuthCode().
     */
    public function setAuthCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = NULL) {
        try {
            $this->db->{self::COLLECTION_CODES}->insert(array(
                "_id" => $code,
                "client_id" => $client_id,
                "user_id" => $user_id,
                "redirect_uri" => $redirect_uri,
                "expires" => $expires,
                "scope" => $scope
            ));
        } catch (MongoException $e) {
            $this->handleException($e);
        }
    }
    
    /**
     * @see IOAuth2GrantCode::unsetExpiredAuthCodes()
     */
    public function unsetExpiredAuthCodes($older_than) {
        $this->removeExpired($older_than, FALSE);
    }

    /**
     * Creates a refresh or access token
     * 
     * @param string $token - Access or refresh token id
     * @param string $client_id
     * @param mixed $user_id
     * @param int $expires
     * @param string $scope
     * @param bool $isRefresh
     */
    protected function setToken($token, $client_id, $user_id, $expires, $scope, $isRefresh = TRUE) {
        try {
            $collection = $isRefresh ? self::COLLECTION_REFRESH : self::COLLECTION_TOKENS;

            $this->db->$collection->insert(array(
                '_id' => $token,
                'client_id' => $client_id,
                'user_id' => $user_id,
                'expires' => $expires,
                'scope' => $scope
            ));
        } catch (MongoException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Retrieves an access or refresh token.
     *  
     * @param string $token
     * @param bool $refresh
     */
    protected function getToken($token, $isRefresh = true) {
        try {
            $collection = $isRefresh ? self::COLLECTION_REFRESH : self::COLLECTION_TOKENS;

            $result = $this->db->$collection->findOne(array('_id' => $token));
            return $result;
        } catch (MongoException $e) {
            $this->handleException($e);
        }
    }
    
    protected function getTokenByClientAndUser($client_id, $user_id) {
        try {
            $result = $this->db->{self::COLLECTION_TOKENS}->findOne(array('client_id' => $client_id, 'user_id' => $user_id));
            return $result;
        } catch (MongoException $e) {
            $this->handleException($e);
        }
    }

    /**
     * Remove expired tokens
     * 
     * @param bool $isRefresh 
     */
    protected function removeExpired($olderThan, $isRefresh = FALSE) {
        try {
            $collection = $isRefresh ? self::COLLECTION_REFRESH : self::COLLECTION_TOKENS;

            $result = $this->db->$collection->remove(
                    array('expires' => array(
                    '$gt' => 0,
                    '$lte' => $olderThan
                    )), array('safe' => TRUE, 'multiple' => TRUE)
            );

            return $result['ok'];
        } catch (MongoException $e) {
            $this->handleException($e);
        }
    }

    /**
     * @see IOAuth2Storage::checkRestrictedGrantType()
     */
    public function checkRestrictedGrantType($client_id, $grant_type) {
        return TRUE; // Not implemented
    }

    /**
     * Change/override this to whatever your own password hashing method is.
     * 
     * @param string $secret
     * @return string
     */
    protected function hash($client_secret, $client_id) {
        return hash('sha1', $client_id . $client_secret . self::SALT);
    }

    /**
     * Checks the password.
     * Override this if you need to
     * 
     * @param string $client_id
     * @param string $client_secret
     * @param string $actualPassword
     */
    protected function checkPassword($try, $client_secret, $client_id) {
        return $try == $this->hash($client_secret, $client_id);
    }

}

?>
