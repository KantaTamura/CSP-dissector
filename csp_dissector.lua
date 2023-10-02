-- Proto definition
-- "CSP"
--  ├── "CAN Frame Header"
--  └── "Extended Header"
local proto_csp     = Proto("CSP", "Cubusat Space Protocol")
local proto_csp_can = Proto("CSP_CAN_Frame_Header", "CSP - CAN Frame Header")
local proto_csp_xtd = Proto("CSP_Extendnd_Header",  "CSP - Extended Header")

-- Other Protocol Field
local sll_pkt_f  = Field.new("sll.pkttype")
local sll_type_f = Field.new("sll.ltype")
local can_xtd_f  = Field.new("can.flags.xtd")
local data_len_f = Field.new("data.len")
local can_pad_f  = Field.new("can.padding")

-- Constants
local SLL_TYPE_CAN  = 0x000C
local CAN_FRAME_LEN = 8

-- CSP CAN Fields
local f_can = proto_csp_can.fields
f_can.prio              = ProtoField.uint32("csp.prio",             "Prio",             base.DEC, nil, 0x18000000)
f_can.destination       = ProtoField.uint32("csp.destination",      "Destination",      base.DEC, nil, 0x07FFE000)
f_can.sender            = ProtoField.uint32("csp.sender",           "Sender",           base.DEC, nil, 0x00001F80)
f_can.source_count      = ProtoField.uint32("csp.source_count",     "Source Count",     base.DEC, nil, 0x00000060)
f_can.fragment_counter  = ProtoField.uint32("csp.fragment_counter", "Fragment Counter", base.DEC, nil, 0x0000001C)
f_can.begin             = ProtoField.uint32("csp.begin",            "Begin",            base.DEC, nil, 0x00000002)
f_can.end_              = ProtoField.uint32("csp.end",              "End",              base.DEC, nil, 0x00000001)

-- CSP Extended Fields
local f_xtd = proto_csp_xtd.fields
f_xtd.source            = ProtoField.uint32("csp.source",           "Source",           base.DEC, nil, 0xFFFC0000)
f_xtd.destination_port  = ProtoField.uint32("csp.destination_port", "Destination Port", base.DEC, nil, 0x0003F000)
f_xtd.source_port       = ProtoField.uint32("csp.source_port",      "Source Port",      base.DEC, nil, 0x00000FC0)
f_xtd.flags             = ProtoField.uint32("csp.flags",            "Flags",            base.DEC, nil, 0x0000003F)

-- CSP CAN Dissector
function proto_csp.dissector(buffer, pinfo, tree)
    -- 32bit little endian to big endian
    local function le_to_be(little_bits, start)
        local buf = ByteArray.new()
        buf:append(little_bits:bytes(start + 3, 1))
        buf:append(little_bits:bytes(start + 2, 1))
        buf:append(little_bits:bytes(start + 1, 1))
        buf:append(little_bits:bytes(start, 1))
        return buf:tvb("csp_can_field big_endian")
    end

    -- get fields
    local sll_pkt  = sll_pkt_f()
    local sll_type = sll_type_f()
    local can_xtd  = can_xtd_f()
    local data_len = data_len_f()
    local can_pad  = can_pad_f()

    -- only CSP packet (possibility)
    if not(sll_type and can_xtd and data_len) then return end
    if buffer:len() == 0 or sll_type.value ~= SLL_TYPE_CAN or not(can_xtd.value) then return end

    pinfo.cols.protocol = proto_csp.name

    local can_pad_len = 0
    if can_pad then
        can_pad_len = can_pad.len
    end

    local can_frame_start = buffer:len() - data_len.value - can_pad_len - CAN_FRAME_LEN
    local csp_frame_start = buffer:len() - data_len.value - can_pad_len

    -- CSP
    local subtree = tree:add(proto_csp, buffer(can_frame_start))
    subtree:add(f.can_frame_header, buffer(can_frame_start, 4):le_uint())

    -- CSP CAN Frame Header
    local csp_can_header = buffer(can_frame_start, 4)
    local can_frame_tree = subtree:add(proto_csp_can, csp_can_header)
    can_frame_tree:add_le(f_can.prio,             csp_can_header)
    can_frame_tree:add_le(f_can.destination,      csp_can_header)
    can_frame_tree:add_le(f_can.sender,           csp_can_header)
    can_frame_tree:add_le(f_can.source_count,     csp_can_header)
    can_frame_tree:add_le(f_can.fragment_counter, csp_can_header)
    can_frame_tree:add_le(f_can.begin,            csp_can_header)
    can_frame_tree:add_le(f_can.end_,             csp_can_header)

    -- csp-frame fix endian
    local csp_can_header_big = le_to_be(buffer, can_frame_start):range(0, 4)
    local csp_dst      = csp_can_header_big:bitfield(5, 14)
    local csp_sender   = csp_can_header_big:bitfield(19, 6)
    local csp_src_cnt  = csp_can_header_big:bitfield(25, 2)
    local csp_frag_cnt = csp_can_header_big:bitfield(27, 3)
    local csp_begin    = csp_can_header_big:bitfield(30, 1)
    local csp_end      = csp_can_header_big:bitfield(31, 1)

    -- table key
    local key = tostring(sll_pkt) .. ":" .. tostring(csp_sender) .. ":" .. tostring(csp_dst) .. ":" .. tostring(csp_src_cnt)

     -- CSP Extended Header
    if csp_begin == 1 then
        local csp_xtd_header = buffer(csp_frame_start, 4)
        local xtd_frame_tree = subtree:add(proto_csp_xtd, csp_xtd_header)
        xtd_frame_tree:add(f_xtd.source,            csp_xtd_header)
        xtd_frame_tree:add(f_xtd.destination_port,  csp_xtd_header)
        xtd_frame_tree:add(f_xtd.source_port,       csp_xtd_header)
        xtd_frame_tree:add(f_xtd.flags,             csp_xtd_header)

        if ExtendedTable[key] == nil then
            ExtendedTable[key] = { header=buffer:bytes(csp_frame_start, 4) }
        end
    elseif not(ExtendedTable[key] == nil) then
        local xtd = ExtendedTable[key].header:tvb("csp_xtd_header")

        local xtd_frame_tree = subtree:add(proto_csp_xtd, xtd())
        xtd_frame_tree:add(f_xtd.source,            xtd())
        xtd_frame_tree:add(f_xtd.destination_port,  xtd())
        xtd_frame_tree:add(f_xtd.source_port,       xtd())
        xtd_frame_tree:add(f_xtd.flags,             xtd())
    end
end

function proto_csp.init()
    ExtendedTable = {}
end

register_postdissector(proto_csp)
