


const scrypt = require('./scrypt');

const wrapResultForCallback = (err, verified) => {
    console.log(err, verified);
}

const testHash = (algo, password, hashSettings) => {
    switch(algo) {
        case 'scrypt':
            scrypt(password, hashSettings, wrapResultForCallback);    
            break;
    }
}

const testHashSettings =  {
    "algorithm": "scrypt",
    "hash": {
        "value": "lugzEQYD8QEe+7nA+ldPiJoD+jATYhuVUnzbW0OQ4XasBKWvMBZbrydBExlf7j6fSpSTv46YhoOvc6HLH8Uvyg==",
        "encoding": "base64"       
    },
    "salt": {
      "value":"CFAFE413A6384300ABE7FF288A33016Ab2cdd6f2ec4242d6a44236abe2e181ff",
      "encoding": "ascii"
    },
    "password": {
        "encoding": "utf16le"
    },
    "costfactor": 131072,
    "blocksize": 8,
    "parallelization": 1,
    "keylength": 64
}

testHash('scrypt', 'TESThashFORauth0@2201', testHashSettings);

