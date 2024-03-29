-- Proto definition
-- "CSP"
--  ├── "CAN Frame Header"
--  ├── "Extended Header"
--  └── "Data"
local proto_csp      = Proto("CSPv2", "Cubusat Space Protocol version 2.0")
local proto_csp_can  = Proto("CSPv2_CAN_Frame_Header", "CSP 2.0 - CAN Frame Header")
local proto_csp_xtd  = Proto("CSPv2_Extendnd_Header",  "CSP 2.0 - Extended Header")
local proto_csp_data = Proto("CSPv2_DATA", "CSP 2.0 - Data")

-- Other Protocol Field
local can_xtd_f  = Field.new("can.flags.xtd")
local data_len_f = Field.new("data.len")
local can_len_f  = Field.new("can.len")
local can_pad_f  = Field.new("can.padding")

-- Constants
local SLL_TYPE_CAN  = 0x000C
local CAN_FRAME_LEN = 8
local CSP_EXTENDED_FRAME_LEN = 4

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

-- CSP Data Fields
local f_data = proto_csp_data.fields
f_data.data  = ProtoField.string("csp.data", "Data", base.UNICODE)

-- CSP CAN Dissector
function proto_csp.dissector(buffer, pinfo, tree)
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
    local subtree = tree:add(proto_csp, buffer(can_frame_start))

    -- CSP CAN Frame Header
    local csp_can_header = buffer(can_frame_start, 4)
    local can_frame_tree = subtree:add(proto_csp_can, csp_can_header)
    can_frame_tree:add(f_can.prio,             csp_can_header)
    can_frame_tree:add(f_can.destination,      csp_can_header)
    can_frame_tree:add(f_can.sender,           csp_can_header)
    can_frame_tree:add(f_can.source_count,     csp_can_header)
    can_frame_tree:add(f_can.fragment_counter, csp_can_header)
    can_frame_tree:add(f_can.begin,            csp_can_header)
    can_frame_tree:add(f_can.end_,             csp_can_header)

    -- csp-frame fix endian
    local csp_dst      = csp_can_header:bitfield(5, 14)
    local csp_sender   = csp_can_header:bitfield(19, 6)
    local csp_src_cnt  = csp_can_header:bitfield(25, 2)
    local csp_frag_cnt = csp_can_header:bitfield(27, 3)
    local csp_begin    = csp_can_header:bitfield(30, 1)
    local csp_end      = csp_can_header:bitfield(31, 1)

    -- table key
    local key
    local base = tostring(csp_sender) .. ":" .. tostring(csp_dst) .. ":" .. tostring(csp_src_cnt)
    if pinfo.visited == false and csp_begin == 1 then
        local buf = base
        local id = csp_src_cnt
        while DataTable[buf] and DataTable[buf].ended == true do
            id = id + 4
            buf = tostring(csp_sender) .. ":" .. tostring(csp_dst) .. ":" .. tostring(id)
        end
        key = buf
        if KeyTable[base] == nil then
            KeyTable[base] = {}
        end
        table.insert(KeyTable[base], { start = pinfo.number, key = key })
    else
        for i = 1, #KeyTable[base] do
            if KeyTable[base][i].start > pinfo.number then
                break
            end
            key = KeyTable[base][i].key
        end
    end

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

    -- CSP Data
    if DataTable[key] == nil then
        DataTable[key] = { ended=false, fragments={} }
    end

    if pinfo.visited == false then
        local extended_header_len = 0
        if csp_begin == 1 then
            extended_header_len = CSP_EXTENDED_FRAME_LEN
        end

        local id = csp_frag_cnt
        while not(DataTable[key].fragments[id] == nil) do
            id = id + 8
        end
        DataTable[key].fragments[id] = { data=buffer:bytes(csp_frame_start + extended_header_len, can_len.value - extended_header_len) }
    end

    if csp_end == 1 then
        DataTable[key].ended = true
    end

    if DataTable[key].ended == true then
        local buf = ByteArray.new()
        for i = 0, #DataTable[key].fragments do
            buf:append( DataTable[key].fragments[i].data )
        end
        local d = buf:tvb("merged data")
        local data_tree = subtree:add(proto_csp_data, d())
        data_tree:add(f_data.data, d())
    end

    -- pinfo
    pinfo.cols.protocol = proto_csp.name
    pinfo.cols.src = csp_sender
    pinfo.cols.dst = csp_dst
end

function proto_csp.init()
    ExtendedTable = {}
    DataTable = {}
    KeyTable = {}
end

register_postdissector(proto_csp)
