<?php

namespace Trikoder\Bundle\OAuth2Bundle\Converter;

use Trikoder\Bundle\OAuth2Bundle\League\Entity\Scope as ScopeEntity;
use Trikoder\Bundle\OAuth2Bundle\Model\Scope as ScopeModel;

final class ScopeConverter
{
    public function toDomain(ScopeEntity $scope): ScopeModel
    {
        return new ScopeModel($scope->getIdentifier());
    }

    /**
     * @return ScopeModel[]
     */
    public function toDomainArray(array $scopes): array
    {
        return array_map(function (ScopeEntity $scope): ScopeModel {
            return $this->toDomain($scope);
        }, $scopes);
    }

    public function toLeague(ScopeModel $scope): ScopeEntity
    {
        $scopeEntity = new ScopeEntity();
        $scopeEntity->setIdentifier((string) $scope);

        return $scopeEntity;
    }

    /**
     * @return ScopeEntity[]
     */
    public function toLeagueArray(array $scopes): array
    {
        return array_map(function (ScopeModel $scope): ScopeEntity {
            return $this->toLeague($scope);
        }, $scopes);
    }
}
