<?php

class Translator
{
    public static function getTranslation($lang_messages, $key)
    {
        return $lang_messages[$key] ?? $key;
    }
}

