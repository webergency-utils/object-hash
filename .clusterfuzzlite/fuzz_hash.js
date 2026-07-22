const { FuzzedDataProvider } = require('@jazzer.js/core');
const objectHash = require('../dist/hash.cjs');

/**
 * Recursively construct a rich, semi-random JavaScript data structure
 * using bytes from Jazzer.js FuzzedDataProvider.
 */
function createFuzzedObject(provider, depth = 0, maxDepth = 4) {
    if (depth >= maxDepth) {
        return provider.consumeString(20);
    }

    const typeChoice = provider.consumeIntegralInRange(0, 14);

    switch (typeChoice) {
        case 0:
            return provider.consumeString(provider.consumeIntegralInRange(0, 50));
        case 1:
            return provider.consumeNumber();
        case 2:
            return provider.consumeBoolean();
        case 3:
            return null;
        case 4:
            return undefined;
        case 5:
            return Symbol(provider.consumeString(10));
        case 6:
            try {
                return BigInt(provider.consumeIntegralInRange(-10000, 10000));
            } catch {
                return 0n;
            }
        case 7:
            return new Date(provider.consumeIntegralInRange(0, 2000000000000));
        case 8:
            try {
                return new RegExp(provider.consumeString(10), provider.pickValue(['g', 'i', 'm', 'u', 's', '']));
            } catch {
                return /fuzz/;
            }
        case 9:
            return Buffer.from(provider.consumeBytes(provider.consumeIntegralInRange(0, 32)));
        case 10:
            return new Uint8Array(provider.consumeBytes(provider.consumeIntegralInRange(0, 16)));
        case 11: {
            const arr = [];
            const count = provider.consumeIntegralInRange(0, 4);
            for (let i = 0; i < count; i++) {
                arr.push(createFuzzedObject(provider, depth + 1, maxDepth));
            }
            return arr;
        }
        case 12: {
            const set = new Set();
            const count = provider.consumeIntegralInRange(0, 3);
            for (let i = 0; i < count; i++) {
                set.add(createFuzzedObject(provider, depth + 1, maxDepth));
            }
            return set;
        }
        case 13: {
            const map = new Map();
            const count = provider.consumeIntegralInRange(0, 3);
            for (let i = 0; i < count; i++) {
                const key = createFuzzedObject(provider, depth + 1, maxDepth);
                const val = createFuzzedObject(provider, depth + 1, maxDepth);
                map.set(key, val);
            }
            return map;
        }
        case 14:
        default: {
            const obj = {};
            const count = provider.consumeIntegralInRange(0, 4);
            for (let i = 0; i < count; i++) {
                const key = provider.consumeString(10) || `key_${i}`;
                obj[key] = createFuzzedObject(provider, depth + 1, maxDepth);
            }
            return obj;
        }
    }
}

module.exports.fuzz = function(data) {
    try {
        const provider = new FuzzedDataProvider(data);

        // 1. Build complex, deeply nested payload
        const payload = createFuzzedObject(provider);

        // 2. Randomly insert circular reference to test cycle detection
        if (typeof payload === 'object' && payload !== null && provider.consumeBoolean()) {
            try {
                payload.circularRef = payload;
            } catch {
                // Readonly objects
            }
        }

        // 3. Fuzz Options construction
        const algorithms = ['cyrb64', 'murmur3', 'sha256', 'fast', 'balanced', 'strong'];
        const encodings = ['hex', 'base36', 'base62', 'base64', 'base64url', 'binary', 'buffer'];
        const bitLengths = [64, 96, 128, 192, 256];

        const options = {
            algorithm: provider.pickValue(algorithms),
            encoding: provider.pickValue(encodings),
            bitLength: provider.pickValue(bitLengths),
            sortArrays: provider.consumeBoolean(),
            ignoreUndefinedProperties: provider.consumeBoolean(),
            excludeValues: provider.consumeBoolean(),
            excludeKeys: provider.consumeBoolean() ? [provider.consumeString(5)] : undefined,
            includeKeys: provider.consumeBoolean() ? [provider.consumeString(5)] : undefined
        };

        // 4. Test core functions
        const strResult = objectHash.objectStringify(payload, options);
        const hashResult = objectHash.default(payload, options);
        const bytesResult = objectHash.objectHashBytes(payload, options);

        if (!(bytesResult instanceof Uint8Array)) {
            throw new Error('objectHashBytes must return a Uint8Array');
        }

        // 5. Test Hasher class API
        const hasher = new objectHash.Hasher(options);
        hasher.stringify(payload);
        hasher.hash(payload);

        // 6. Test StreamingHash API
        const streamer = hasher.createHash();
        streamer.update(payload);
        streamer.update(provider.consumeString(20));
        const streamHash = streamer.digest();
        const streamBytes = streamer.digestBytes();
        streamer.reset();

        if (typeof streamHash !== 'string' || !(streamBytes instanceof Uint8Array)) {
            throw new Error('StreamingHash returned invalid types');
        }

    } catch (e) {
        // Allow expected argument type errors or RangeErrors from invalid crypto options if any
        if (e instanceof RangeError || e instanceof TypeError) {
            return;
        }
        throw e;
    }
};
