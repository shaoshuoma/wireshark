
-- custom_extractor.lua
-- �Զ���������ȡ�ű�

-- ����һ��tap
local tap = Listener.new()

-- ����ļ�
local output_file = io.open("extracted_data.json", "w")
local packet_count = 0

function tap.packet(pinfo, tvb)
    packet_count = packet_count + 1
    
    -- ��ȡ��Ҫ���ֶ�
    local packet_info = {
        number = pinfo.number,
        timestamp = tostring(pinfo.abs_ts),
        src = tostring(pinfo.src),
        dst = tostring(pinfo.dst),
        protocol = pinfo.cols.protocol,
        length = pinfo.len
    }
    
    -- �����TCP������ȡ������Ϣ
    local tcp_info = pinfo.cols.info
    if tcp_info then
        packet_info.info = tcp_info
    end
    
    -- д��JSON��ʽ
    output_file:write(table.concat({
        '{"packet":', packet_count, 
        ',"data":', json_encode(packet_info), '}\n'
    }))
    
    -- ÿ1000��ˢ��һ��
    if packet_count % 1000 == 0 then
        output_file:flush()
        print("�Ѵ���", packet_count, "�����ݰ�")
    end
end

function tap.draw()
    print("������ȡ��ɣ�������", packet_count, "�����ݰ�")
    output_file:close()
end

-- �򵥵�JSON���뺯��
function json_encode(obj)
    local json_str = "{"
    for k, v in pairs(obj) do
        json_str = json_str .. '"' .. k .. '":"' .. tostring(v) .. '",'
    end
    return json_str:sub(1, -2) .. "}"
end
