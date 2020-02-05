<?php

namespace Idaas\OpenID;

use ArieTimmerman\Passport\TokenCache;
use Illuminate\Http\Request;

class UserInfo
{
    public function respondToUserInfoRequest(
        Request $request,
        UserRepository $userRepositoryOIDC
    ) {
        return resolve(TokenCache::class)->rememberUserInfo($request->user()->token()->id, function () use ($request, $userRepositoryOIDC) {
            $token = $request->user()->token();
            $scopes = $token->scopes;

            $claims = $token->claims;

            if (empty($claims)) {
                $claims = [];
            }

            if (!isset($claims['userinfo'])) {
                $claims['userinfo'] = [];
            }

            foreach ($scopes as $scope) {
                foreach ($userRepositoryOIDC->getClaims($scope) as $claim) {
                    if (!isset($claims['userinfo'][$claim])) {
                        $claims['userinfo'][$claim] = null;
                    }
                }
            }

            return $request->user()->toUserInfo($claims, $scopes);
        });
    }
}
