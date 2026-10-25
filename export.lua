--exp
local bit = bit32
local K = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
}

local function sha256(msg)
    local len = #msg
    local bits = len * 8
    msg = msg .. "\128" .. string.rep("\0", (55 - len) % 64)
        .. string.pack(">I4I4", math.floor(bits / 2^32), bits % 2^32)

    local h0,h1,h2,h3,h4,h5,h6,h7 =
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19

    local w = {}
    for chunk = 1, #msg, 64 do
        for i = 0, 15 do
            w[i + 1] = string.unpack(">I4", msg, chunk + i * 4)
        end
        for i = 17, 64 do
            local a, b = w[i - 15], w[i - 2]
            local s0 = bit.bxor(bit.rrotate(a, 7), bit.rrotate(a, 18), bit.rshift(a, 3))
            local s1 = bit.bxor(bit.rrotate(b, 17), bit.rrotate(b, 19), bit.rshift(b, 10))
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) % 2^32
        end

        local a,b,c,d,e,f,g,h = h0,h1,h2,h3,h4,h5,h6,h7
        for i = 1, 64 do
            local S1 = bit.bxor(bit.rrotate(e, 6), bit.rrotate(e, 11), bit.rrotate(e, 25))
            local ch = bit.bxor(bit.band(e, f), bit.band(bit.bnot(e), g))
            local t1 = (h + S1 + ch + K[i] + w[i]) % 2^32
            local S0 = bit.bxor(bit.rrotate(a, 2), bit.rrotate(a, 13), bit.rrotate(a, 22))
            local maj = bit.bxor(bit.band(a, b), bit.band(a, c), bit.band(b, c))
            local t2 = (S0 + maj) % 2^32
            h, g, f, e, d, c, b, a = g, f, e, (d + t1) % 2^32, c, b, a, (t1 + t2) % 2^32
        end

        h0 = (h0 + a) % 2^32; h1 = (h1 + b) % 2^32
        h2 = (h2 + c) % 2^32; h3 = (h3 + d) % 2^32
        h4 = (h4 + e) % 2^32; h5 = (h5 + f) % 2^32
        h6 = (h6 + g) % 2^32; h7 = (h7 + h) % 2^32
    end

    return string.format("%08x%08x%08x%08x%08x%08x%08x%08x", h0,h1,h2,h3,h4,h5,h6,h7)
end

local function serialize(func)
    local parts = {}
  
    local numparams, is_vararg = debug.info(func, "a")
    parts[#parts + 1] = string.char(is_vararg and 1 or 0, numparams % 256)
    local constants = debug.getconstants(func)
  
    for i = 1, #constants do
        local c = constants[i]
        local t = typeof(c)

        if t == "nil" then
            parts[#parts + 1] = "\0"
        elseif t == "string" then
            parts[#parts + 1] = c
        elseif t == "number" then
            parts[#parts + 1] = string.pack("<d", c)
        elseif t == "boolean" then
            parts[#parts + 1] = c and "\1" or "\0"
        elseif t == "vector" then
            parts[#parts + 1] = string.pack("<fff", c.X, c.Y, c.Z)
        elseif t == "table" then
            local keys = {}
            for k in pairs(c) do
                if type(k) == "string" then keys[#keys + 1] = k end
            end
            table.sort(keys)
            for _, k in ipairs(keys) do parts[#parts + 1] = k end
        elseif t == "function" then
            if iscclosure(c) then
                parts[#parts + 1] = "C"
            else
                parts[#parts + 1] = serialize(c)
            end
        end
    end

    for index, this in debug.getprotos(func) do
        parts[#parts + 1] = serialize(this)
    end

    return table.concat(parts)
end

return function(func)
    if (iscclosure(func)) then task.spawn(error, "Cannot hash a C Closure!"); return; end
    return sha256(serialize(func))
end
