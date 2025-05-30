<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) EllaiSys <support@ellaisys.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ellaisys\Cognito\Guards\Traits;

use Aws\Result as AwsResult;

use Illuminate\Support\Facades\Log;
use Illuminate\Contracts\Auth\Authenticatable;

use Ellaisys\Cognito\AwsCognitoClaim;

use Exception;
use Ellaisys\Cognito\Exceptions\AwsCognitoException;
use Ellaisys\Cognito\Exceptions\NoLocalUserException;
use Ellaisys\Cognito\Exceptions\InvalidUserModelException;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;

/**
 * Trait Base Cognito Guard
 */
trait CognitoMFA
{

    /**
     * Attempt MFA based Authentication
     */
    public function attemptBaseMFA(array $challenge = [], bool $remember=false) {
        try {
            //Reset global variables
            $this->challengeName = null;
            $this->challengeData = null;
            $this->claim = null;
            $this->awsResult = null;

            $challengeName = $challenge['challenge_name'];
            $session = $challenge['session'];
            $challengeValue = $challenge['mfa_code'];
            $username = $challenge['username'];

            //Attempt MFA Challenge
            $result = $this->client->authMFAChallenge($challengeName, $session, $challengeValue, $username);

            //Check if the result is an instance of AwsResult
            if (!empty($result) && $result instanceof AwsResult) {
                //Set value into class param
                $this->awsResult = $result;

                //Check in case of any challenge
                if (isset($result['ChallengeName'])) {
                    $this->challengeName = $result['ChallengeName'];
                    $this->challengeData = $this->handleCognitoChallenge($result, $username);
                } elseif (isset($result['AuthenticationResult'])) {
                    //Create claim token
                    $this->claim = new AwsCognitoClaim($result, null);
                } else {
                    throw new HttpException(400, 'ERROR_AWS_COGNITO_MFA_CODE_NOT_PROPER');
                } //End if
            } //End if
    
            return $result;
        } catch(CognitoIdentityProviderException | Exception $e) {
            throw $e;
        } //Try-catch ends
    } //Function ends


    /**
     * Associate the MFA Software Token
     *
     * @param  string $appName (optional)
     *
     * @return array
     */
    public function associateSoftwareTokenMFA(string $appName=null, string $userParamToAddToQR='email') {
        try {
            //Get Access Token
            $accessToken = $this->cognito->getToken();
            if (!empty($accessToken)) {
                $response = $this->client->associateSoftwareTokenMFA($accessToken);
                if (!empty($response)) {
                    //Build payload
                    $secretCode = $response->get('SecretCode');
                    $username = $this->user()[$userParamToAddToQR];
                    $appName = (!empty($appName))?:config('app.name');
                    $uriTotp = 'otpauth://totp/'.$appName.' ('.$username.')?secret='.$secretCode.'&issuer='.config('app.name');
                    $payload = [
                        'SecretCode' => $secretCode,
                        'SecretCodeQR' => config('cognito.mfa_qr_library').$uriTotp,
                        'TotpUri' => $uriTotp
                    ];
                    return $payload;
                } //End if
            } else {
                return null;
            } //End if
        } catch(Exception $e) {
            throw $e;
        } //Try-catch ends
    } //Function ends


    /**
     * Verify the MFA Software Token
     * 
     * @param  string  $guard
     * @param  string  $userCode
     * @param  string  $deviceName (optional)
     *
     * @return array
     */
    public function verifySoftwareTokenMFA(string $userCode, string $deviceName=null) {
        try {
            //Get Access Token
            $accessToken = $this->cognito->getToken();
            if (!empty($accessToken)) {
                $response = $this->client->verifySoftwareTokenMFA($userCode, $accessToken, null, $deviceName);
                if (!empty($response)) {
                    $payload = [
                        'Status' => $response->get('Status')
                    ];
                    return $payload;
                } //End if
            } else {
                return null;
            } //End if
        } catch(Exception $e) {
            if ($e instanceof CognitoIdentityProviderException) {
                throw new HttpException(400, $e->getAwsErrorMessage(), $e);
            } //End if
            throw $e;
        } //Try-catch ends
    } //Function ends
    
} //Trait ends