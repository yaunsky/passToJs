/**
 *@param username
 *@param passwordOrgin
 *@return encrypt password for $username who use orign password $passwordOrgin
 *
 **/

function encrypt(username, passwordOrgin) {
    return hex_sha1(username+hex_sha1(passwordOrgin));
}



function hex_sha1(s, hexcase) {
    if (!(arguments) || !(arguments.length) || arguments.length < 1) {
        return binb2hex(core_sha1(AlignSHA1("aiact@163.com")), true);
    } else {
        if (arguments.length == 1) {
            return binb2hex(core_sha1(AlignSHA1(arguments[0])), true);
        } else {
            return binb2hex(core_sha1(AlignSHA1(arguments[0])), arguments[1]);
        }
    }
   // return binb2hex(core_sha1(AlignSHA1(s)),hexcase);
}
/**/
/*
 * Perform a simple self-test to see if the VM is working
 */
function sha1_vm_test() {
    return hex_sha1("abc",false) == "a9993e364706816aba3e25717850c26c9cd0d89d";
}
/**/
/*
 * Calculate the SHA-1 of an array of big-endian words, and a bit length
 */
function core_sha1(blockArray) {
    var x = blockArray;  //append padding
    var w = Array(80);
    var a = 1732584193;
    var b = -271733879;
    var c = -1732584194;
    var d = 271733878;
    var e = -1009589776;
    for (var i = 0; i < x.length; i += 16) {  //每次处理512位 16*32
        var olda = a;
        var oldb = b;
        var oldc = c;
        var oldd = d;
        var olde = e;
        for (var j = 0; j < 80; j += 1) {  //对每个512位进行80步操作
            if (j < 16) {
                w[j] = x[i + j];
            } else {
                w[j] = rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
            }
            var t = safe_add(safe_add(rol(a, 5), sha1_ft(j, b, c, d)), safe_add(safe_add(e, w[j]), sha1_kt(j)));
            e = d;
            d = c;
            c = rol(b, 30);
            b = a;
            a = t;
        }
        a = safe_add(a, olda);
        b = safe_add(b, oldb);
        c = safe_add(c, oldc);
        d = safe_add(d, oldd);
        e = safe_add(e, olde);
    }
    return new Array(a, b, c, d, e);
}
/**/
/*
 * Perform the appropriate triplet combination function for the current iteration
 * 返回对应F函数的值
 */
function sha1_ft(t, b, c, d) {
    if (t < 20) {
        return (b & c) | ((~b) & d);
    }
    if (t < 40) {
        return b ^ c ^ d;
    }
    if (t < 60) {
        return (b & c) | (b & d) | (c & d);
    }
    return b ^ c ^ d;  //t<80
}
/**/
/*

 * Determine the appropriate additive constant for the current iteration
 * 返回对应的Kt值
 */
function sha1_kt(t) {
    return (t < 20) ? 1518500249 : (t < 40) ? 1859775393 : (t < 60) ? -1894007588 : -899497514;
}
/**/
/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 * 将32位数拆成高16位和低16位分别进行相加，从而实现 MOD 2^32 的加法
 */
function safe_add(x, y) {
    var lsw = (x & 65535) + (y & 65535);
    var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 65535);
}
/**/
/*
 * Bitwise rotate a 32-bit number to the left.
 * 32位二进制数循环左移
 */
function rol(num, cnt) {
    return (num << cnt) | (num >>> (32 - cnt));
}
/**/
/*

 * The standard SHA1 needs the input string to fit into a block

 * This function align the input string to meet the requirement

 */
function AlignSHA1(str) {
    var nblk = ((str.length + 8) >> 6) + 1, blks = new Array(nblk * 16);
    for (var i = 0; i < nblk * 16; i += 1) {
        blks[i] = 0;
    }
    for (i = 0; i < str.length; i += 1) {
        blks[i >> 2] |= str.charCodeAt(i) << (24 - (i & 3) * 8);
    }
    blks[i >> 2] |= 128 << (24 - (i & 3) * 8);
    blks[nblk * 16 - 1] = str.length * 8;
    return blks;
}
/**/
/*
 * Convert an array of big-endian words to a hex string.
 */
function binb2hex(binarray, hexcase) {
    var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
    var str = "";
    for (var i = 0; i < binarray.length * 4; i += 1) {
        str += hex_tab.charAt((binarray[i >> 2] >> ((3 - i % 4) * 8 + 4)) & 15) + hex_tab.charAt((binarray[i >> 2] >> ((3 - i % 4) * 8)) & 15);
    }
    return str;
}

