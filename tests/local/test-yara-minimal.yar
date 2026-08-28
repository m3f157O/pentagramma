rule test
{
    strings:
        $a = /bypass.{0,40}executionpolicy/ nocase
    condition:
        $a
}
