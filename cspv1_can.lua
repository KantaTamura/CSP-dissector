-- Proto definition
-- "CSPv1"
--  ├── "CAN Frame Header"
--  ├── "Extended Header"
--  └── "Data"
local proto_csp1      = Proto("CSPv1", "Cubusat Space Protocol version 1.0")
local proto_csp1_can  = Proto("CSPv1_CAN_Frame_Header", "CSPv1 - CAN Frame Header")
local proto_csp1_xtd  = Proto("CSPv1_Extendnd_Header",  "CSPv1 - Extended Header")
local proto_csp1_data = Proto("CSPv1_DATA", "CSPv1 - Data")

-- Other Protocol Field
local sll_pkt_f  = Field.new("sll.pkttype")
local sll_type_f = Field.new("sll.ltype")
local can_xtd_f  = Field.new("can.flags.xtd")
local data_len_f = Field.new("data.len")
local can_len_f  = Field.new("can.len")
local can_pad_f  = Field.new("can.padding")

-- Constants
local SLL_TYPE_CAN  = 0x000C
local CAN_FRAME_LEN = 8
local CSP_EXTENDED_FRAME_LEN = 6

-- CSP CAN Fields
local f_can = proto_csp1_can.fields
f_can.src    = ProtoField.uint32("csp1.src",    "Source",      base.DEC, nil, 0x1F000000)
f_can.dst    = ProtoField.uint32("csp1.dst",    "Destination", base.DEC, nil, 0x00F80000)
f_can.flag   = ProtoField.uint32("csp1.flag",   "Flag",        base.DEC, nil, 0x00040000)
f_can.remain = ProtoField.uint32("csp1.remain", "Remain",      base.DEC, nil, 0x0003FC00)
f_can.id     = ProtoField.uint32("csp1.id",     "ID",          base.DEC, nil, 0x000003FF)

-- CSP Extended Fields
local f_xtd = proto_csp1_xtd.fields
f_xtd.pri    = ProtoField.uint32("csp1.xtd.pri",   "Priority",            base.DEC, nil, 0xC0000000)
f_xtd.src    = ProtoField.uint32("csp1.xtd.src",   "Source Address",      base.DEC, nil, 0x3E000000)
f_xtd.dst    = ProtoField.uint32("csp1.xtd.dst",   "Destination Address", base.DEC, nil, 0x01F00000)
f_xtd.dport  = ProtoField.uint32("csp1.xtd.dport", "Destination Port",    base.DEC, nil, 0x000FC000)
f_xtd.sport  = ProtoField.uint32("csp1.xtd.sport", "Source Port",         base.DEC, nil, 0x00003F00)
f_xtd.flags  = ProtoField.uint32("csp1.xtd.flags", "Flags",               base.DEC, nil, 0x000000FF)
f_xtd.length = ProtoField.uint16("csp1.xtd.len",   "Data Length",         base.DEC)

-- CSP Data Fields
local f_data = proto_csp1_data.fields
f_data.data  = ProtoField.string("csp1.data", "Data", base.UNICODE)

-- CSP CAN Dissector
function proto_csp1.dissector(buffer, pinfo, tree)
    -- 32bit little endian to big endian
    local function le_to_be(little_bits, start)
        local buf = ByteArray.new()
        buf:append(little_bits:bytes(start + 3, 1))
        buf:append(little_bits:bytes(start + 2, 1))
        buf:append(little_bits:bytes(start + 1, 1))
        buf:append(little_bits:bytes(start, 1))
        return buf:tvb("csp1_can_field big_endian")
    end

    -- get fields
    local can_xtd  = can_xtd_f()
    local data_len = data_len_f()
    local can_len  = can_len_f()
    local can_pad  = can_pad_f()

    -- only CSP packet (possibility)
    if not(can_xtd and data_len) then return end
    if buffer:len() == 0 or not(can_xtd.value) then return end

    local can_pad_len = 0
    if can_pad then
        can_pad_len = can_pad.len
    end

    local can_frame_start = buffer:len() - data_len.value - can_pad_len - CAN_FRAME_LEN
    local csp_frame_start = buffer:len() - data_len.value - can_pad_len

    -- CSP
    local subtree = tree:add(proto_csp1, buffer(can_frame_start))

    -- CSP CAN Frame Header
    local csp_can_header = buffer(can_frame_start, 4)
    local can_frame_tree = subtree:add(proto_csp1_can, csp_can_header)
    can_frame_tree:add_le(f_can.src,    csp_can_header)
    can_frame_tree:add_le(f_can.dst,    csp_can_header)
    can_frame_tree:add_le(f_can.flag,   csp_can_header)
    can_frame_tree:add_le(f_can.remain, csp_can_header)
    can_frame_tree:add_le(f_can.id,     csp_can_header)

    -- csp-frame fix endian
    local csp_can_header_big = le_to_be(buffer, can_frame_start):range(0, 4)
    local csp_src    = csp_can_header_big:bitfield(3, 5)
    local csp_dst    = csp_can_header_big:bitfield(8, 5)
    local csp_remain = csp_can_header_big:bitfield(14, 8)
    local csp_id     = csp_can_header_big:bitfield(22, 10)

    -- table key
    local key = tostring(csp_src) .. ":" .. tostring(csp_dst) .. ":" .. tostring(csp_id)

    -- CSP Extended Header
    if ExtendedTable[key] == nil then
        ExtendedTable[key] = { header=buffer:bytes(csp_frame_start, 6) }
    end

    local xtd = ExtendedTable[key].header:tvb("csp1_xtd_header")
    local xtd_frame_tree = subtree:add(proto_csp1_xtd, xtd())
    xtd_frame_tree:add(f_xtd.pri,    xtd(0, 4))
    xtd_frame_tree:add(f_xtd.src,    xtd(0, 4))
    xtd_frame_tree:add(f_xtd.dst,    xtd(0, 4))
    xtd_frame_tree:add(f_xtd.dport,  xtd(0, 4))
    xtd_frame_tree:add(f_xtd.sport,  xtd(0, 4))
    xtd_frame_tree:add(f_xtd.flags,  xtd(0, 4))
    xtd_frame_tree:add(f_xtd.length, xtd(4, 2))

    -- CSP Data
    local extended_header_len = 0
    if DataTable[key] == nil then
        DataTable[key] = { ended=false, fragments={} }
        extended_header_len = CSP_EXTENDED_FRAME_LEN
    end

    if pinfo.visited == false then
        DataTable[key].fragments[csp_remain] = { data=buffer:bytes(csp_frame_start + extended_header_len, can_len.value - extended_header_len) }
    end

    if csp_remain == 0 then
        DataTable[key].ended = true
    end

    if DataTable[key].ended == true then
        local buf = ByteArray.new()
        for i = 0, #DataTable[key].fragments do
            buf:prepend( DataTable[key].fragments[i].data )
        end
        local d = buf:tvb("csp1_data")
        local data_tree = subtree:add(proto_csp1_data, d())
        data_tree:add(f_data.data, d())
    end

    -- pinfo
    pinfo.cols.protocol = proto_csp1.name
    pinfo.cols.src = csp_src
    pinfo.cols.dst = csp_dst
end

function proto_csp1.init()
    ExtendedTable = {}
    DataTable = {}
end

register_postdissector(proto_csp1)
