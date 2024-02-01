﻿namespace fbctl
{
    public class FlashBladeSettings
    {
        public string? Name { get; init; }
        public string? ManagementIpFqdn { get; init; }
        public string? ClientId { get; init; }
        public string? KeyId { get; init; }   
        public string? Issuer { get; init; }
        public string? Username { get; init; }    
        public string? PrivateKeyPath { get; init; }  
    }
}
