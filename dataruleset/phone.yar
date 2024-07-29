rule person_private_info : pii
{
    meta:
        description = "personal private data"
        threat_level = 3
        level = 3
        class = "pii"

    strings:
        $a = "address"
        $b = "phone"
        $c = "name"

    condition:
        $a or $b or $c
}