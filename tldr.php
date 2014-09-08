<?php

/*
a handler that mod_rewrite uses
checks the filename passed by the visitor
against a 'database' of files that it knows the
whereabouts of
and then return a 302 Found redirection but with
TLDR headers to help the visitor verify the integrity
of the file

example:

URL: https://www.bennish.net/tldr/example.tar.gz
mod_rewrite internally redirects to
/tldr/handler.php?file=example.tar.gz

and we use metadata of the form..

metadata/example.tar.gz/location.txt
metadata/example.tar.gz/md5.txt
metadata/example.tar.gz/sha1.txt
metadata/example.tar.gz/sha256.txt
metadata/example.tar.gz/sha512.txt

which we return in the headers of "HTTP/1.1 302 Found" response
*/


function pageNotFound()
{
    header($_SERVER['SERVER_PROTOCOL'].' 404 Not Found');
    echo <<<EOF
<!DOCTYPE html>
<html>
<head>
<title>File not found</title>
</head>
<body>
<h1>File not found</h1>
<p>The file you requested can not be found.</p>
</body>
</html>
EOF;
    exit;
}


function getFileContents($filename)
{
    if (is_readable($filename))
    {
        return rtrim(file_get_contents($filename));
    }
    return false;
}


define('METADATA_DIR', __DIR__.'/metadata/');


if (!empty($_GET['file']))
{
    $pwd = realpath(__DIR__);
    $metadataDir = realpath(METADATA_DIR.$_GET['file']);

    if ($metadataDir)
    {
        if (substr($metadataDir, 0, strlen($pwd)) !== $pwd)
        {
            // metadataDir is not a subdirectory of the current directory
            pageNotFound();
        }

        if (is_dir($metadataDir))
        {
            $location = getFileContents($metadataDir.'/location.txt');

            if (!$location)
                // if we cannot redirect to a location, throw a 404
                pageNotFound();

            $md5  = getFileContents($metadataDir.'/md5.txt');
            $sha1 = getFileContents($metadataDir.'/sha1.txt');
            $sha256 = getFileContents($metadataDir.'/sha256.txt');
            $sha512 = getFileContents($metadataDir.'/sha512.txt');

            // -------
            // Checksums - part one
            if ($md5)    header('TLDR-Checksum-MD5: '.$md5);
            if ($sha1)   header('TLDR-Checksum-SHA1: '.$sha1);
            if ($sha256) header('TLDR-Checksum-SHA256: '.$sha256);
            if ($sha512) header('TLDR-Checksum-SHA512: '.$sha512);

            // ------
            // GPG signature - part two.. do this bit later
            //
            // How is this process going to work?
            //
            // Minimum requirements:
            //  - Need a file that relates to the download file (e.g. text file with filename and checksums)
            //    that is signed by a key that we trust
            //
            // But how can we trust this person?
            //
            // 1. Via our existing key chain and the GPG web of trust - unlikely to be helpful for non-veteran GPG users
            // 2. We trust this HTTPS site (https://www.bennish.net), this site specifies the Key ID and if this matches
            //    the key used in the signature file, we:
            //    a) trust the key for the one time purpose of verifying the file integrity (as a one time trust)
            //    b) add the key to our key chain and/or increase the trust level of it
            //
            // see: http://mirror.catn.com/pub/centos/7.0.1406/isos/x86_64/sha256sum.txt.asc

            //header('TLDR-GPG-Signature: https://www.bennish.net/sigs/'.rawurlencode($_GET[file]).'.sig');
            //header('TLDR-GPG-Signature: https://www.bennish.net/sigs/'.rawurlencode($_GET[file]).'.asc');

            // not entirely necessary - the key ID can be determined from the sig file
            // but perhaps if the sig file above is remotely hosted, we can enhance trust by specifying the
            // expected signer's key ID
            //header('TLDR-GPG-Key-ID: 0x4F25E3B6');

            // we can also provide a URL from where to fetch the public key
            // if provided over https, this might enhance trust in the key too
            //header('TLDR-GPG-Key-URL: https://www.bennish.net/keys/ben_kennish_4096_rsa_public_gpg.asc');

            header('Location: '.$location);
            exit;
        }
        else
        {
            pageNotFound();
        }
    }
    else
    {
        pageNotFound();
    }

}



include_once '../library/bennish.inc.php';


$options = array ('title' => 'Trusted Linker Download Redirection (TLDR)',
                  'stylesheet' => '../bennish.css',
                  'canonicalURL' => 'https://'.$_SERVER['HTTP_HOST'].$_SERVER['SCRIPT_URL'],
                 );

showHeader($options);


?>
<h2>Trusted Linker Download Redirection</h2>

<p>This page is used to demonstrate <abbr title="Trusted Linker Download Redirection">TLDR</abbr>.</p>

<h3>What's this TLDR thing? (less technical)</h3>

<p>
Most people know about "https" and that it improves security on the web. The problem is that it's a big stress
for servers so more often than not, files you download, even programs/apps that will run on your computer,
are not delivered using https. This is a bit of a problem as you no longer have the protection that https provides.
TLDR provides a way that an https site can link to a non-https download and tell your web browser more info about the file
so that the browser can verify that the file hasn't been modified.
</p>

<h3>How does TLDR work? (more technical)</h3>

<p>
TLDR is a proposed extension to <abbr title="Hyper Text Transfer Protocol">HTTP</abbr>. All of the download links below
redirect (using a "302 Found" HTTP response) to a non-https URL where the file can be found and downloaded.  Special
TLDR headers are sent within the 302 response which contain one or more checksums of the files (e.g.
<a href="http://en.wikipedia.org/wiki/SHA-1">SHA1</a>).  With support from the web browser,
the files can have their checksums calculated once downloaded to ensure that the file data is as expected.
</p>

<h2>Downloading files using TLDR</h2>

<h3>1. Install Firefox Add-On</h3>

<p>
To try out TLDR, download and install <a href='<?php echo 'https://'.$_SERVER['HTTP_HOST']; ?>/files/tldr.xpi'>my prototype
TLDR Firefox Add-on</a> (open the tldr.xpi file with Firefox).
</p>

<h3>2. Download files</h3>

<?php

if (empty($_SERVER['HTTPS']))
{
    echo '<p><span style="color:red">WARNING</span>: you are using the non-https version of this page.  As such, TLDR will deliberately not function on these links.
    Please visit <a href="https://'.$_SERVER['HTTP_HOST'].$_SERVER['SCRIPT_URL'].'">the https version of this page</a> if you wish to test TLDR Firefox Add-On.</p>'.PHP_EOL;
}
elseif (empty($_GET['forceHTTP']))
{
    echo '<p>NOTE: TLDR is disabled for links that don\'t use https.  If you want to observe this, please visit the <a href="http://'.$_SERVER['HTTP_HOST'].$_SERVER['SCRIPT_URL'].'">the http version of this page</a>.</p>'.PHP_EOL;
}

?>

<ul>
<?php

$ls = scandir(METADATA_DIR);

foreach ($ls as $file)
{
    if (substr($file, 0, 1) == '.') continue; // ignore files that start with '.'

    if (is_dir(METADATA_DIR.$file))
    {
        $description = getFileContents(METADATA_DIR.$file.'/description.txt');
        echo '<li><a href="'.rawurlencode($file).'">'.htmlspecialchars($file).'</a>';
        if ($description) echo ' - '.htmlspecialchars($description);
        echo '</li>'.PHP_EOL;
    }
    else
        echo '<li>'.htmlspecialchars($file).'</li>'.PHP_EOL;
}
?>
</ul>

<?php

showFooter();