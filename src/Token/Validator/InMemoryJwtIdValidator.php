<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Validator;

final class InMemoryJwtIdValidator implements JwtIdValidatorInterface
{
    /**
     * @var array<string, bool>
     */
    private array $denyList = [];

    /**
     * @var array<string, bool>
     */
    private array $allowList = [];
    
    private bool $useAllowList;

    /**
     * @param array<string>|null $allowList
     * @param array<string> $denyList
     */
    public function __construct(
        ?array $allowList = null, 
        ?array $denyList = null,
        bool $useAllowList = false
    ){
        if ($allowList !== null) {
            $this->allowList = $this->normalizeList($allowList);
        }
        
        if($denyList !== null){
            $this->denyList = $this->normalizeList($denyList);
        }

        $this->useAllowList = $useAllowList;
    }

    public function isAllowed(?string $jwtId): bool
    {
        if (isset($this->denyList[$jwtId])) {
            return false;
        }
        
        if(! $this->useAllowList){
            return true;
        }
        
        if( $jwtId === null){
            return false;
        }

        return isset($this->allowList[$jwtId]);
    }

    /**
     * @param array<string> $list
     *
     * @return array<string, bool>
     */
    private function normalizeList(array $list): array
    {
        $normalized = [];

        foreach ($list as $value) {
            $normalized[$value] = true;
        }

        return $normalized;
    }
}
