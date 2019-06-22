<?php
namespace Neas;
// In production we dont need this line.
//require_once __DIR__ . './../vendor/autoload.php';

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;

use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

use Jose\Component\Checker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\AlgorithmChecker;

use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\JWSVerifier;

class JWT {

    public static function getAlgorithm(string $type){
        $type = strtoupper($type);
        switch($type){
            case 'HS256':
                return new HS256();
            case 'HS384':
                return new HS384();
            case 'HS512':
                return new HS512();
            default:
                return new HS256();
        }
    }
    public static function generateOCTKey(int $size=1024, string $alg='HS256'):JWK{
        return JWKFactory::createOctKey($size,[
            'alg'=>$alg,
            'use'=>'sig'
        ]);
    }

    public static function generateFromSecretKey(string $secret, string $alg='HS256'):JWK{
        return JWKFactory::createFromSecret($secret,[
            'alg'=>$alg,
            'use'=>'sig'
        ]);
    }

    public static function getToken(array $payload , string $octKey , string $algorithmUsed='HS256'):string{
        
        $key = new JWK([
            'kty'=>'oct',
            'k'=>$octKey
        ]);

        $algorithmManager = new AlgorithmManager([self::getAlgorithm($algorithmUsed)]);
        $jwsBuilder = new JWSBuilder($algorithmManager);
        $jws = $jwsBuilder
        ->create()                               // We want to create a new JWS
        ->withPayload(json_encode($payload))                  // We set the payload
        ->addSignature($key, ['alg' => $algorithmUsed]) // We add a signature with a simple protected header
        ->build();                               // We build it
        $serializer = new CompactSerializer(); // The serializer
        $token = $serializer->serialize($jws, 0); // We serialize the signature at index 0 (we only have one signature).
        return $token;
    }

    public static function verifyToken(string $token , string $octKey , string $algorithmUsed='HS256'){

        $key = new JWK([
            'kty'=>'oct',
            'k'=>$octKey
        ]);

        // $headerCheckerManager = new HeaderCheckerManager(
        //     [
        //         new AlgorithmChecker([$algorithmUsed]), // We check the header "alg" (algorithm)
        //     ],
        //     [
        //         new JWSTokenSupport(), // Adds JWS token type support
        //     ]
        // );
        // $headerCheckerManager->check($token, 0, ['alg', 'enc', 'crit']);


        $algorithmManager = new AlgorithmManager([
            JWT::getAlgorithm($algorithmUsed)
        ]);
        
        // We instantiate our JWS Verifier.
        $jwsVerifier = new JWSVerifier(
            $algorithmManager
        );

        $serializerManager = new JWSSerializerManager([
            new CompactSerializer(),
        ]);

        // The algorithm manager with the HS256 algorithm.

        
        // The input we want to check
        // We try to load the token.
        $jws = $serializerManager->unserialize($token);

        $claimCheckerManager = new ClaimCheckerManager(
            [
                new Checker\IssuedAtChecker(),
                new Checker\NotBeforeChecker(),
                new Checker\ExpirationTimeChecker(),
            ]
        );
        
        $result=[
            'payload'=>$jws->getPayload(),
            'isVerified'=>(bool) $jwsVerifier->verifyWithKey($jws, $key, 0),
        ];

        try {
            $claims = json_decode($jws->getPayload(), true);
            $claimsResult = $claimCheckerManager->check($claims,['iat','nbf','exp']);
            $result['errors']=null;
        } catch (\Throwable $th) {
            $result['errors']=$th->getMessage();
        }
        
        return $result;
    }

}


/**
 * //Example
 * $octKey = JWT::generateOCTKey(1024)->get('k');
 * $octKey = 'qVCxQyJiSs1htEAC8RQRFFDUeyOSHzy3xZLw4L-B7Fg3LGvbOswTtjZy9kTXbGkkQCR9zUrLcFSiYMT4NderX3jRbVqodrfMn-SDiXmnm6m7jgTALfuJm3Bt_9PZb-P8s5d4T8kkNvRp_2OS3K7hjUO4jup36teK50y-VThZHYQ';
 * $token = JWT::getToken(['iat'=>time(),'nbf'=> time() ,'exp'=>time()+3600],$octKey);
 * print_r(JWT::verifyToken($token,$octKey));
 */
