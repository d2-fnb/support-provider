lazy_static::lazy_static! {
pub static ref T: std::collections::HashMap<&'static str, &'static str> =
    [
        ("Status", "Trạng thái hiện tại"),
        ("Your Desktop", "Desktop của bạn"),
        ("desk_tip", "Desktop của bạn có thể đuợc truy cập bằng ID và mật khẩu này."),
        ("Password", "Mật khẩu"),
        ("Ready", "Sẵn sàng"),
        ("Established", "Đã đuợc thiết lập"),
        ("connecting_status", "Đang kết nối đến mạng lưới RustDesk..."),
        ("Enable service", "Bật dịch vụ"),
        ("Start service", "Bắt đầu dịch vụ"),
        ("Service is running", "Dịch vụ hiện đang chạy"),
        ("Service is not running", "Dịch vụ hiện đang dừng"),
        ("not_ready_status", "Hiện chưa sẵn sàng. Hãy kiểm tra kết nối của bạn"),
        ("Control Remote Desktop", "Điều khiển Desktop Từ Xa"),
        ("Transfer file", "Truyền Tệp Tin"),
        ("Connect", "Kết nối"),
        ("Recent sessions", "Các session gần đây"),
        ("Address book", "Quyển địa chỉ"),
        ("Confirmation", "Xác nhận"),
        ("TCP tunneling", "TCP tunneling"),
        ("Remove", "Loại bỏ"),
        ("Refresh random password", "Làm mới mật khẩu ngẫu nhiên"),
        ("Set your own password", "Đặt mật khẩu riêng"),
        ("Enable keyboard/mouse", "Cho phép sử dụng bàn phím/chuột"),
        ("Enable clipboard", "Cho phép sử dụng clipboard"),
        ("Enable file transfer", "Cho phép truyền tệp tin"),
        ("Enable TCP tunneling", "Cho phép TCP tunneling"),
        ("IP Whitelisting", "Cho phép IP"),
        ("ID/Relay Server", "Máy chủ ID/chuyển tiếp"),
        ("Import server config", "Nhập cấu hình máy chủ"),
        ("Export Server Config", "Xuất cấu hình máy chủ"),
        ("Import server configuration successfully", "Nhập cấu hình máy chủ thành công"),
        ("Export server configuration successfully", "Xuất cấu hình máy chủ thành công"),
        ("Invalid server configuration", "Cấu hình máy chủ không hợp lệ"),
        ("Clipboard is empty", "Khay nhớ tạm trống"),
        ("Stop service", "Dừng dịch vụ"),
        ("Change ID", "Thay đổi ID"),
        ("Your new ID", "ID mới của bạn"),
        ("length %min% to %max%", "độ dài %min% đến %max%"),
        ("starts with a letter", "bắt đầu bằng một chữ"),
        ("allowed characters", "các ký tự cho phép"),
        ("id_change_tip", "Các kí tự đuợc phép là: từ a-z, A-Z, 0-9 và _ (dấu gạch dưới). Kí tự đầu tiên phải bắt đầu từ a-z, A-Z. Độ dài kí tự từ 6 đến 16"),
        ("Website", "Trang web"),
        ("About", "Giới thiệu"),
        ("Slogan_tip", ""),
        ("Privacy Statement", "Bảo Mật Thông tin"),
        ("Mute", "Tắt tiếng"),
        ("Build Date", "Ngày xuất bản"),
        ("Version", "Phiên bản"),
        ("Home", "Trang chủ"),
        ("Audio Input", "Đầu vào âm thanh"),
        ("Enhancements", "Các tiện ích"),
        ("Hardware Codec", "Codec phần cứng"),
        ("Adaptive bitrate", "Bitrate thích ứng"),
        ("ID Server", "Máy chủ ID"),
        ("Relay Server", "Máy chủ Chuyển tiếp"),
        ("API Server", "Máy chủ API"),
        ("invalid_http", "phải bắt đầu bằng http:// hoặc https://"),
        ("Invalid IP", "IP không hợp lệ"),
        ("Invalid format", "Định dạng không hợp lệnh"),
        ("server_not_support", "Chưa đuợc hỗ trợ bởi máy chủ"),
        ("Not available", "Chưa có mặt"),
        ("Too frequent", "Quá thường xuyên"),
        ("Cancel", "Hủy"),
        ("Skip", "Bỏ qua"),
        ("Close", "Đóng"),
        ("Retry", "Thử lại"),
        ("OK", "OK"),
        ("Password Required", "Yêu cầu mật khẩu"),
        ("Please enter your password", "Mời nhập mật khẩu"),
        ("Remember password", "Nhớ mật khẩu"),
        ("Wrong Password", "Sai mật khẩu"),
        ("Do you want to enter again?", "Bạn có muốn nhập lại không?"),
        ("Connection Error", "Kết nối bị lỗi"),
        ("Error", "Lỗi"),
        ("Reset by the peer", "Đựoc cài đặt lại bởi người dùng từ xa"),
        ("Connecting...", "Đang kết nối..."),
        ("Connection in progress. Please wait.", "Đang kết nối. Vui lòng chờ."),
        ("Please try 1 minute later", "Hãy thử lại sau 1 phút"),
        ("Login Error", "Đăng nhập bị lỗi"),
        ("Successful", "Thành công"),
        ("Connected, waiting for image...", "Đã kết nối, đang đợi hình ảnh..."),
        ("Name", "Tên"),
        ("Type", "Loại"),
        ("Modified", "Chỉnh sửa"),
        ("Size", "Kích cỡ"),
        ("Show Hidden Files", "Hiển thị tệp tin bị ẩn"),
        ("Receive", "Nhận"),
        ("Send", "Gửi"),
        ("Refresh File", "Làm mới tệp tin"),
        ("Local", "Cục bộ"),
        ("Remote", "Từ xa"),
        ("Remote Computer", "Máy tính từ xa"),
        ("Local Computer", "Máy tính cục bộ"),
        ("Confirm Delete", "Xác nhận xóa"),
        ("Delete", "Xóa"),
        ("Properties", "Thuộc tính"),
        ("Multi Select", "Chọn nhiều"),
        ("Select All", "Chọn tất cả"),
        ("Unselect All", "Bỏ chọn tất cả"),
        ("Empty Directory", "Thư mục rỗng"),
        ("Not an empty directory", "Không phải thư mục rỗng"),
        ("Are you sure you want to delete this file?", "Bạn chắc bạn có muốn xóa tệp tin này không?"),
        ("Are you sure you want to delete this empty directory?", "Bạn chắc bạn có muốn xóa thư mục rỗng này không?"),
        ("Are you sure you want to delete the file of this directory?", "Bạn chắc bạn có muốn xóa những tệp tin trong thư mục này không?"),
        ("Do this for all conflicts", "Xác nhận đối với tất cả các trùng lặp"),
        ("This is irreversible!", "Không thể hoàn tác!"),
        ("Deleting", "Đang xóa"),
        ("files", "các tệp tin"),
        ("Waiting", "Đang chờ"),
        ("Finished", "Hoàn thành"),
        ("Speed", "Tốc độ"),
        ("Custom Image Quality", "Chất lượng hình ảnh"),
        ("Privacy mode", "Chế độ riêng tư"),
        ("Block user input", "Chặn các tương tác từ người dùng"),
        ("Unblock user input", "Hủy chặn các tương tác từ người dùng"),
        ("Adjust Window", "Điều chỉnh cửa sổ"),
        ("Original", "Gốc"),
        ("Shrink", "Thu nhỏ"),
        ("Stretch", "Kéo giãn"),
        ("Scrollbar", "Thanh cuộn"),
        ("ScrollAuto", "Tự động cuộn"),
        ("Good image quality", "Chất lượng hình ảnh tốt"),
        ("Balanced", "Cân bằng"),
        ("Optimize reaction time", "Tối ưu thời gian phản ứng"),
        ("Custom", "Tùy chỉnh"),
        ("Show remote cursor", "Hiển thị con trỏ từ máy từ xa"),
        ("Show quality monitor", "Hiện thị chất lượng của màn hình"),
        ("Disable clipboard", "Tắt clipboard"),
        ("Lock after session end", "Khóa sau khi kết thúc phiên kết nối"),
        ("Insert Ctrl + Alt + Del", "Cài Ctrl + Alt + Del"),
        ("Insert Lock", "Cài khóa"),
        ("Refresh", "Làm mới"),
        ("ID does not exist", "ID không tồn tại"),
        ("Failed to connect to rendezvous server", "Không thể kết nối đến máy chủ rendezvous"),
        ("Please try later", "Thử lại sau"),
        ("Remote desktop is offline", "Máy tính từ xa hiện đang offline"),
        ("Key mismatch", "Chìa không khớp"),
        ("Timeout", "Quá thời gian"),
        ("Failed to connect to relay server", "Không thể kết nối tới máy chủ chuyển tiếp"),
        ("Failed to connect via rendezvous server", "Không thể kết nối qua máy chủ rendezvous"),
        ("Failed to connect via relay server", "Không thể kết nối qua máy chủ chuyển tiếp"),
        ("Failed to make direct connection to remote desktop", "Không thể kết nối thẳng tới máy tính từ xa"),
        ("Set Password", "Cài đặt mật khẩu"),
        ("OS Password", "Mật khẩu hệ điều hành"),
        ("install_tip", "Do UAC, RustDesk sẽ không thể hoạt động đúng cách là bên từ xa trong vài trường hợp. Để tránh UAC, hãy nhấn cái nút dưới đây để cài RustDesk vào hệ thống."),
        ("Click to upgrade", "Nhấn để nâng cấp"),
        ("Click to download", "Nhấn để tải xuống"),
        ("Click to update", "Nhấn để cập nhật"),
        ("Configure", "Cài đặt"),
        ("config_acc", "Để có thể điều khiển máy tính từ xa, bạn cần phải cung cấp quyền \"Trợ năng\" cho RustDesk"),
        ("config_screen", "Để có thể truy cập máy tính từ xa, bạn cần phải cung cấp quyền \"Ghi Màn Hình\" cho RustDesk."),
        ("Installing ...", "Đang cài ..."),
        ("Install", "Cài"),
        ("Installation", "Cài"),
        ("Installation Path", "Địa điểm cài"),
        ("Create start menu shortcuts", "Tạo shortcut tại start menu"),
        ("Create desktop icon", "Tạo biểu tượng trên desktop"),
        ("agreement_tip", "Bằng cách bắt đầu cài đặt, bạn chấp nhận thỏa thuận cấp phép."),
        ("Accept and Install", "Chấp nhận và Cài"),
        ("End-user license agreement", "Thỏa thuận cấp phép dành cho người dùng"),
        ("Generating ...", "Đang tạo ..."),
        ("Your installation is lower version.", "Phiên bản của bạn là phiên bản cũ"),
        ("not_close_tcp_tip", "Đừng đóng cửa sổ này khi bạn đang sử dụng tunnel"),
        ("Listening ...", "Đang nghe ..."),
        ("Remote Host", "Máy từ xa"),
        ("Remote Port", "Cổng từ xa"),
        ("Action", "Hành động"),
        ("Add", "Thêm"),
        ("Local Port", "Cổng nội bộ"),
        ("Local Address", "Địa chỉ nội bộ"),
        ("Change Local Port", "Thay đổi cổng nội bộ"),
        ("setup_server_tip", "Để kết nối nhanh hơn, hãy tự tạo máy chủ riêng"),
        ("Too short, at least 6 characters.", "Quá ngắn, độ dài phải ít nhất là 6."),
        ("The confirmation is not identical.", "Xác minh không khớp"),
        ("Permissions", "Quyền"),
        ("Accept", "Chấp nhận"),
        ("Dismiss", "Bỏ qua"),
        ("Disconnect", "Ngắt kết nối"),
        ("Enable file copy and paste", "Cho phép sao chép và dán tệp tin"),
        ("Connected", "Đã kết nối"),
        ("Direct and encrypted connection", "Kết nối trực tiếp và đuợc mã hóa"),
        ("Relayed and encrypted connection", "Kết nối chuyển tiếp và mã hóa"),
        ("Direct and unencrypted connection", "Kết nối trực tiếp và không đuợc mã hóa"),
        ("Relayed and unencrypted connection", "Kết nối chuyển tiếp và không đuợc mã hóa"),
        ("Enter Remote ID", "Nhập ID từ xa"),
        ("Enter your password", "Nhập mật khẩu"),
        ("Logging in...", "Đang đăng nhập"),
        ("Enable RDP session sharing", "Cho phép chia sẻ phiên kết nối RDP"),
        ("Auto Login", "Tự động đăng nhập"),
        ("Enable direct IP access", "Cho phép truy cập trực tiếp qua IP"),
        ("Rename", "Đổi tên"),
        ("Space", "Dấu cách"),
        ("Create desktop shortcut", "Tạo shortcut trên desktop"),
        ("Change Path", "Đổi địa điểm"),
        ("Create Folder", "Tạo thư mục"),
        ("Please enter the folder name", "Hãy nhập tên thư mục"),
        ("Fix it", "Sửa nó"),
        ("Warning", "Cảnh báo"),
        ("Login screen using Wayland is not supported", "Màn hình đăng nhập sử dụng Wayland không được hỗ trợ"),
        ("Reboot required", "Yêu cầu khởi động lại"),
        ("Unsupported display server", "Máy chủ hiển thị không đuợc hỗ trọ"),
        ("x11 expected", "Cần x11"),
        ("Port", "Cổng"),
        ("Settings", "Cài đặt"),
        ("Username", "Tên người dùng"),
        ("Invalid port", "Cổng không hợp lệ"),
        ("Closed manually by the peer", "Đã đóng thủ công bởi người dùng từ xa"),
        ("Enable remote configuration modification", "Cho phép thay đổi cấu hình bên từ xa"),
        ("Run without install", "Chạy mà không cần cài đặt"),
        ("Connect via relay", "Kết nối qua máy chủ chuyển tiếp"),
        ("Always connect via relay", "Luôn kết nối qua máy chủ chuyển tiếp"),
        ("whitelist_tip", "Chỉ có những IP đựoc cho phép mới có thể truy cập"),
        ("Login", "Đăng nhập"),
        ("Verify", "Xác thực"),
        ("Remember me", "Nhớ tài khoản"),
        ("Trust this device", "Tin thiết bị này"),
        ("Verification code", "Mã xác thực"),
        ("verification_tip", "Bạn đang đăng nhập trên một thiết bị mới, một mã xác thực đã được gửi tới email đăng ký của bạn, hãy nhập mã xác thực để tiếp tục đăng nhập."),
        ("Logout", "Đăng xuất"),
        ("Tags", "Tags"),
        ("Search ID", "Tìm ID"),
        ("whitelist_sep", "Đuợc cách nhau bởi dấu phẩy, dấu chấm phẩy, dấu cách hay dòng mới"),
        ("Add ID", "Thêm ID"),
        ("Add Tag", "Thêm Tag"),
        ("Unselect all tags", "Hủy chọn tất cả các tag"),
        ("Network error", "Lỗi mạng"),
        ("Username missed", "Mất tên người dùng"),
        ("Password missed", "Mất mật khẩu"),
        ("Wrong credentials", "Chứng danh bị sai"),
        ("The verification code is incorrect or has expired", ""),
        ("Edit Tag", "Chỉnh sửa Tag"),
        ("Forget Password", "Quên mật khẩu"),
        ("Favorites", "Ưa thích"),
        ("Add to Favorites", "Thêm vào mục Ưa thích"),
        ("Remove from Favorites", "Xóa khỏi mục Ưa thích"),
        ("Empty", "Trống"),
        ("Invalid folder name", "Tên thư mục không hợp lệ"),
        ("Socks5 Proxy", "Proxy Socks5"),
        ("Socks5/Http(s) Proxy", "Proxy Socks5/Http(s)"),
        ("Discovered", "Đuợc phát hiện"),
        ("install_daemon_tip", "Để chạy lúc khởi động máy, bạn cần phải cài dịch vụ hệ thống."),
        ("Remote ID", "ID từ xa"),
        ("Paste", "Dán"),
        ("Paste here?", "Dán ở đây?"),
        ("Are you sure to close the connection?", "Bạn có chắc muốn đóng kết nối không"),
        ("Download new version", "Tải về phiên bản mới"),
        ("Touch mode", "Chế độ chạm"),
        ("Mouse mode", "Chế độ dùng chuột"),
        ("One-Finger Tap", "Chạm bằng một ngón tay"),
        ("Left Mouse", "Chuột trái"),
        ("One-Long Tap", "Chạm lâu bằng một ngón tay"),
        ("Two-Finger Tap", "Chạm bằng hai ngón tay"),
        ("Right Mouse", "Chuột phải"),
        ("One-Finger Move", "Di chuyển bằng một ngón tay"),
        ("Double Tap & Move", "Chạm hai lần và di chuyển"),
        ("Mouse Drag", "Di chuyển bằng chuột"),
        ("Three-Finger vertically", "Ba ngón tay theo chiều dọc"),
        ("Mouse Wheel", "Bánh xe lăn trê con chuột"),
        ("Two-Finger Move", "Di chuyển bằng hai ngón tay"),
        ("Canvas Move", "Di chuyển canvas"),
        ("Pinch to Zoom", "Véo để phóng to/nhỏ"),
        ("Canvas Zoom", "Phóng to/nhỏ canvas"),
        ("Reset canvas", "Cài đặt lại canvas"),
        ("No permission of file transfer", "Không có quyền truyền tệp tin"),
        ("Note", "Ghi nhớ"),
        ("Connection", "Kết nối"),
        ("Share Screen", "Chia sẻ màn hình"),
        ("Chat", "Chat"),
        ("Total", "Tổng"),
        ("items", "items"),
        ("Selected", "Đã đuợc chọn"),
        ("Screen Capture", "Ghi màn hình"),
        ("Input Control", "Điều khiển đầu vào"),
        ("Audio Capture", "Ghi âm thanh"),
        ("File Connection", "Kết nối tệp tin"),
        ("Screen Connection", "Kết nối màn hình"),
        ("Do you accept?", "Bạn có chấp nhận không?"),
        ("Open System Setting", "Mở cài đặt hệ thống"),
        ("How to get Android input permission?", "Cách để có quyền nhập trên Android?"),
        ("android_input_permission_tip1", "Để thiết bị từ xa điều khiển thiết bị Android của bạn bằng chuột hoặc chạm, bạn cần cho phép RustDesk sử dụng dịch vụ \"Trợ năng\"."),
        ("android_input_permission_tip2", "Vui lòng chuyển đến trang cài đặt hệ thống tiếp theo, tìm và nhập [Dịch vụ đã cài đặt], bật dịch vụ [RustDesk Input]."),
        ("android_new_connection_tip", "Yêu cầu kiểm soát mới đã được nhận, yêu cầu này muốn kiểm soát thiết bị hiện tại của bạn."),
        ("android_service_will_start_tip", "Bật \"Ghi màn hình\" sẽ tự động khởi động dịch vụ, cho phép các thiết bị khác yêu cầu kết nối với thiết bị của bạn."),
        ("android_stop_service_tip", "Đóng dịch vụ sẽ tự động đóng tất cả các kết nối đã thiết lập."),
        ("android_version_audio_tip", "Phiên bản Android hiện tại không hỗ trợ ghi âm, vui lòng nâng cấp lên Android 10 trở lên."),
        ("android_start_service_tip", "Nhấn [Bắt đầu dịch vụ] hoặc bật quyền [Ghi màn hình] để bắt đầu dịch vụ chia sẻ màn hình"),
        ("android_permission_may_not_change_tip", "Quyền cho các kết nối đã được thiếp lập có thể không được thay đổi ngay cho tới khi kết nối lại"),
        ("Account", "Tài khoản"),
        ("Overwrite", "Ghi đè"),
        ("This file exists, skip or overwrite this file?", "Tệp tin này đã tồn tại, bạn có muốn bỏ qua hay ghi đè lên tệp tin này?"),
        ("Quit", "Thoát"),
        ("Help", "Trợ giúp"),
        ("Failed", "Thất bại"),
        ("Succeeded", "Thành công"),
        ("Someone turns on privacy mode, exit", "Ai đó đã bật chế độ riêng tư, thoát"),
        ("Unsupported", "Không hỗ trợ"),
        ("Peer denied", "Người dùng từ xa đã từ chối"),
        ("Please install plugins", "Hãy cài plugins"),
        ("Peer exit", "Người dùng từ xa đã thoát"),
        ("Failed to turn off", "Không thể tắt"),
        ("Turned off", "Đã tắt"),
        ("Language", "Ngôn ngữ"),
        ("Keep RustDesk background service", "Giữ dịch vụ nền RustDesk"),
        ("Ignore Battery Optimizations", "Bỏ qua các tối ưu pin"),
        ("android_open_battery_optimizations_tip", "Nếu bạn muốn tắt tính năng này, vui lòng chuyển đến trang cài đặt ứng dụng RustDesk tiếp theo, tìm và nhập [Pin], Bỏ chọn [Không hạn chế]"),
        ("Start on boot", "Chạy khi khởi động"),
        ("Start the screen sharing service on boot, requires special permissions", "Chạy dịch vụ chia sẻ màn hình khi khởi động, yêu cầu quyền đặc biệt"),
        ("Connection not allowed", "Kết nối không đuợc phép"),
        ("Legacy mode", "Chế độ cũ"),
        ("Map mode", "Chế độ map"),
        ("Translate mode", "Chế độ phiên dịch"),
        ("Use permanent password", "Sử dụng mật khẩu vĩnh viễn"),
        ("Use both passwords", "Sử dụng cả hai mật khẩu"),
        ("Set permanent password", "Đặt mật khẩu vĩnh viễn"),
        ("Enable remote restart", "Bật khởi động lại từ xa"),
        ("Restart remote device", "Khởi động lại thiết bị từ xa"),
        ("Are you sure you want to restart", "Bạn có chắc bạn muốn khởi động lại không"),
        ("Restarting remote device", "Đang khởi động lại thiết bị từ xa"),
        ("remote_restarting_tip", "Thiết bị từ xa đang khởi động lại, hãy đóng cửa sổ tin nhắn này và kết nối lại với mật khẩu vĩnh viễn sau một khoảng thời gian"),
        ("Copied", "Đã sao chép"),
        ("Exit Fullscreen", "Thoát toàn màn hình"),
        ("Fullscreen", "Toàn màn hình"),
        ("Mobile Actions", "Hành động trên thiết bị di động"),
        ("Select Monitor", "Chọn màn hình"),
        ("Control Actions", "Kiểm soát hành động"),
        ("Display Settings", "Thiết lập hiển thị"),
        ("Ratio", "Tỉ lệ"),
        ("Image Quality", "Chất lượng hình ảnh"),
        ("Scroll Style", "Kiểu cuộn"),
        ("Show Toolbar", "Hiện thanh công cụ"),
        ("Hide Toolbar", "Ẩn thanh công cụ"),
        ("Direct Connection", "Kết nối trực tiếp"),
        ("Relay Connection", "Kết nối chuyển tiếp"),
        ("Secure Connection", "Kết nối an toàn"),
        ("Insecure Connection", "Kết nối không an toàn"),
        ("Scale original", "Quy mô gốc"),
        ("Scale adaptive", "Quy mô thích ứng"),
        ("General", "Chung"),
        ("Security", "Bảo mật"),
        ("Theme", "Chủ đề"),
        ("Dark Theme", "Chủ đề Tối"),
        ("Light Theme", "Chủ đề Sáng"),
        ("Dark", "Tối"),
        ("Light", "Sáng"),
        ("Follow System", "Theo hệ thống"),
        ("Enable hardware codec", "Bật codec phần cứng"),
        ("Unlock Security Settings", "Mở khóa cài đặt bảo mật"),
        ("Enable audio", "Bật âm thanh"),
        ("Unlock Network Settings", "Mở khóa cài đặt mạng"),
        ("Server", "Máy chủ"),
        ("Direct IP Access", "Truy cập trực tiếp qua IP"),
        ("Proxy", ""),
        ("Apply", "Áp dụng"),
        ("Disconnect all devices?", "Ngắt kết nối tất cả thiết bị"),
        ("Clear", "Làm trống"),
        ("Audio Input Device", "Thiết bị âm thanh đầu vào"),
        ("Use IP Whitelisting", "Dùng danh sách các IP cho phép"),
        ("Network", "Mạng"),
        ("Pin Toolbar", "Ghim thanh công cụ"),
        ("Unpin Toolbar", "Bỏ ghim thanh công cụ"),
        ("Recording", "Đang ghi hình"),
        ("Directory", "Thư mục"),
        ("Automatically record incoming sessions", "Tự động ghi những phiên kết nối vào"),
        ("Automatically record outgoing sessions", ""),
        ("Change", "Thay đổi"),
        ("Start session recording", "Bắt đầu ghi hình phiên kết nối"),
        ("Stop session recording", "Dừng ghi hình phiên kết nối"),
        ("Enable recording session", "Bật ghi hình phiên kết nối"),
        ("Enable LAN discovery", "Bật phát hiện mạng nội bộ (LAN)"),
        ("Deny LAN discovery", "Từ chối phát hiện mạng nội bộ (LAN)"),
        ("Write a message", "Viết một tin nhắn"),
        ("Prompt", ""),
        ("Please wait for confirmation of UAC...", "Vui lòng chờ cho phép UAC"),
        ("elevated_foreground_window_tip", "Cửa sổ hiện tại của máy tính từ xa yêu cầu quyền cao hơn để vận hành, nên bạn không thể sử dụng chuột và bàn phím tạm thời. Bạn có thể yêu cầu người dùng từ xa thu nhỏ cửa sổ hiện tại, hoặc nhấn vào nút Cấp Quyền trong cửa sổ quản lý kết nối. Để tránh tính trạng này, chúng tôi gợi ý nên cài đặt phần mềm ở phía thiết bị từ xa."),
        ("Disconnected", "Đã ngắt kết nối"),
        ("Other", "Khác"),
        ("Confirm before closing multiple tabs", "Xác nhận trước khi đóng nhiều cửa sổ"),
        ("Keyboard Settings", "Cài đặt bàn phím"),
        ("Full Access", "Truy cập không giới hạng"),
        ("Screen Share", "Chia sẻ màn hình"),
        ("Wayland requires Ubuntu 21.04 or higher version.", "Wayland yêu cầu phiên bản Ubuntu 21.04 trở lên."),
        ("Wayland requires higher version of linux distro. Please try X11 desktop or change your OS.", "Wayland yêu cầu phiên bản distro linux cao hơn. Vui lòng thử máy tính để bàn X11 hoặc thay đổi hệ điều hành của bạn."),
        ("JumpLink", "View"),
        ("Please Select the screen to be shared(Operate on the peer side).", "Vui lòng Chọn màn hình để chia sẻ (Vận hành ở phía người dùng từ xa)."),
        ("Show RustDesk", "Hiện RustDesk"),
        ("This PC", ""),
        ("or", "hoặc"),
        ("Continue with", "Tiếp tục với"),
        ("Elevate", "Cấp Quyền"),
        ("Zoom cursor", "Phóng to chuột"),
        ("Accept sessions via password", "Chấp nhận phiên kết nối bằng mật khẩu"),
        ("Accept sessions via click", "Chấp nhận phiên kết nối bằng chuột"),
        ("Accept sessions via both", "Chấp nhận phiên kết nối bằng cả hai"),
        ("Please wait for the remote side to accept your session request...", "Vui lòng chờ phía người dùng từ xa chấp nhận kết nối của bạn..."),
        ("One-time Password", "Mật khẩu một lần"),
        ("Use one-time password", "Dùng mật khẩu một lần"),
        ("One-time password length", "Độ dài mật khẩu một lần"),
        ("Request access to your device", "Yêu cầu quyền truy cập vào thiết bị của bạn"),
        ("Hide connection management window", "Ẩn cửa sổ quản lý kết nối"),
        ("hide_cm_tip", "Cho phép ẩn chỉ khi chấp nhận phiên kết nối bằng mật khẩu vĩnh viễn"),
        ("wayland_experiment_tip", "Hỗ trợ cho Wayland đang trong giai đoạn thử nghiệm, vui lòng dùng DX11 nếu bạn muốn sử dụng kết nối không giám sát."),
        ("Right click to select tabs", "Chuột phải để chọn cửa sổ"),
        ("Skipped", "Đã bỏ qua"),
        ("Add to address book", "Thêm vào Quyển địa chỉ"),
        ("Group", "Nhóm"),
        ("Search", "Tìm"),
        ("Closed manually by web console", "Đã đóng thủ công bằng bảng điều khiển web"),
        ("Local keyboard type", "Loại bàn phím cục bộ"),
        ("Select local keyboard type", "Chọn kiểu bàn phím cục bộ"),
        ("software_render_tip", "Nếu bạn đang dùng card đồ họa Nvidia trên Linux và cửa sổ từ xa bị tắt ngay lập tức sau khi kết nối, chuyển sang driver mã nguồn mở Nouveau và chọn sử dụng render bằng phần mềm có thể khắc phục được. Yêu cầu khởi động lại phần mềm."),
        ("Always use software rendering", "Cho phép render bằng phần mềm"),
        ("config_input", "Để điều khiển được máy tính từ xa với bàn phím, bạn cần cho phép RustDesk quyền \"Theo dõi đầu vào\" (Input Monitoring)"),
        ("config_microphone", "Để nói chuyện từ xa, bạn phải cho phép RustDesk quyền \"Ghi âm thanh\" (Record Audio)"),
        ("request_elevation_tip", "Bạn cũng có thể yêu cầu được cấp quyền nếu có người nào đó ở bên phía kết nối."),
        ("Wait", "Chờ"),
        ("Elevation Error", "Cấp Quyền Lỗi"),
        ("Ask the remote user for authentication", "Yêu cầu người dùng từ xa xác thực"),
        ("Choose this if the remote account is administrator", "Chọn cái này nếu tài khoản từ xa là quản trị viên"),
        ("Transmit the username and password of administrator", "Truyền tên tài khoản và mật khẩu của quản trị viên"),
        ("still_click_uac_tip", "Vẫn cần người dùng từ xa nhấn OK trên cửa sổ UAC của RustDesk đang chạy."),
        ("Request Elevation", "Yêu cầu Cấp Quyền"),
        ("wait_accept_uac_tip", "Vui lòng chờ cho người dùng từ xa chấp nhận cửa sổ UAC"),
        ("Elevate successfully", "Cấp quyền thành công"),
        ("uppercase", "chữ hoa"),
        ("lowercase", "chữ thường"),
        ("digit", "chữ số"),
        ("special character", "ký tự đặc biệt"),
        ("length>=8", "độ dài>=8"),
        ("Weak", "Yếu"),
        ("Medium", "Trung bình"),
        ("Strong", "Mạng"),
        ("Switch Sides", "Đổi bên"),
        ("Please confirm if you want to share your desktop?", "Vui lòng xác nhận nếu bạn muốn chia sẻ máy tính?"),
        ("Display", "Hiển thị"),
        ("Default View Style", "Kiểu xem mặc định"),
        ("Default Scroll Style", "Kiểu cuộn mặc định"),
        ("Default Image Quality", "Chất lượng hình ảnh mặc định"),
        ("Default Codec", "Codec mặc định"),
        ("Bitrate", "T"),
        ("FPS", ""),
        ("Auto", "Tự động"),
        ("Other Default Options", "Các tùy chọn mặc định khác"),
        ("Voice call", "Gọi âm thanh"),
        ("Text chat", "Tin nhắn"),
        ("Stop voice call", "Dừng cuộc gọi"),
        ("relay_hint_tip", "Việc kết nối trực tiếp có thể không khả thi, bạn có thể thử kết nối qua máy chủ chuyển tiếp. \nThêm vào đó, nếu bạn muốn sử dụng máy chủ chuyển tiếp trong lần thử đầu tiên, bạn có thể thêm hậu tố \"/r\" vào sau ID, hoặc chọn tùy chọn \"Luôn kết nối qua máy chủ chuyển tiếp\""),
        ("Reconnect", "Kết nối lại"),
        ("Codec", ""),
        ("Resolution", "Độ phân giải"),
        ("No transfers in progress", "Không có tệp tin nào đang được truyền"),
        ("Set one-time password length", "Thiết lập độ dài mật khẩu một lần"),
        ("RDP Settings", "Cài đặt RDP"),
        ("Sort by", "Sắp xếp theo"),
        ("New Connection", "Kết nối mới"),
        ("Restore", "Khôi phục"),
        ("Minimize", "Thu nhỏ"),
        ("Maximize", "Phóng to"),
        ("Your Device", "Thiết bị của bạn"),
        ("empty_recent_tip", "Oops, không có kết nối nào gần đây!\nĐã đến lúc kết nối rồi."),
        ("empty_favorite_tip", "Chưa có người dùng yêu thích nào cả?\nHãy tìm ai đó để kết nối cùng và thêm họ vào danh sách yêu thích!"),
        ("empty_lan_tip", "Ôi không, có vẻ như chúng ta chưa phát hiện ra bất cứ người dùng nào cả."),
        ("empty_address_book_tip", "Ôi bạn ơi, có vẻ như bạn chưa thêm ai vào quyển địa chỉ cả."),
        ("eg: admin", "ví dụ: admin"),
        ("Empty Username", "Tên tài khoản trống"),
        ("Empty Password", "Mật khẩu trống"),
        ("Me", "Tôi"),
        ("identical_file_tip", "Tệp tin này giống hệt với tệp tin của người dùng từ xa"),
        ("show_monitors_tip", "Hiện các màn hình trong thanh công cụ"),
        ("View Mode", "Chế độ xem"),
        ("login_linux_tip", "Bạn cần đăng nhập vào tài khoản Linux từ xa để bật X phiên kết nối"),
        ("verify_rustdesk_password_tip", "Xác thực mật khẩu RustDesk"),
        ("remember_account_tip", "Nhớ tài khoản này"),
        ("os_account_desk_tip", "Tài khoản này đã được dùng để đăng nhập tới hệ điều hành từ xa và kích hoạt phiên kết nối ở chế độ headless"),
        ("OS Account", "Tài khoản hệ điều hành"),
        ("another_user_login_title_tip", "Có người dùng khác đã đăng nhập"),
        ("another_user_login_text_tip", "Ngắt kết nối"),
        ("xorg_not_found_title_tip", "Không tìm thấy Xorg"),
        ("xorg_not_found_text_tip", "Vui lòng cài đặt Xorg"),
        ("no_desktop_title_tip", "Không có desktop khả dụng"),
        ("no_desktop_text_tip", "Vui lòng cài đặt desktop GNOME"),
        ("No need to elevate", "Không cần phải cấp quyền"),
        ("System Sound", "Âm thanh hệ thống"),
        ("Default", "Mặc định"),
        ("New RDP", "RDP mới"),
        ("Fingerprint", ""),
        ("Copy Fingerprint", "Sao chép fingerprint"),
        ("no fingerprints", "không có fingerprints"),
        ("Select a peer", "Chọn một người dùng"),
        ("Select peers", "Chọn nhiều người dùng"),
        ("Plugins", "Tiện ích"),
        ("Uninstall", "Gỡ cài đặt"),
        ("Update", "Cập nhật"),
        ("Enable", "Bật"),
        ("Disable", "Tắt"),
        ("Options", "Tùy chọn"),
        ("resolution_original_tip", "Độ phân giải gốc"),
        ("resolution_fit_local_tip", "Vừa với độ phân giải cục bộ"),
        ("resolution_custom_tip", "Độ phân giải tùy chỉnh"),
        ("Collapse toolbar", "Thu nhỏ thanh công cụ"),
        ("Accept and Elevate", "Chấp nhận và Cấp Quyền"),
        ("accept_and_elevate_btn_tooltip", "Chấp nhận kết nối và cấp các quyền UAC."),
        ("clipboard_wait_response_timeout_tip", ""),
        ("Incoming connection", ""),
        ("Outgoing connection", ""),
        ("Exit", ""),
        ("Open", ""),
        ("logout_tip", ""),
        ("Service", ""),
        ("Start", ""),
        ("Stop", ""),
        ("exceed_max_devices", ""),
        ("Sync with recent sessions", ""),
        ("Sort tags", ""),
        ("Open connection in new tab", ""),
        ("Move tab to new window", ""),
        ("Can not be empty", ""),
        ("Already exists", ""),
        ("Change Password", ""),
        ("Refresh Password", ""),
        ("ID", ""),
        ("Grid View", ""),
        ("List View", ""),
        ("Select", ""),
        ("Toggle Tags", ""),
        ("pull_ab_failed_tip", ""),
        ("push_ab_failed_tip", ""),
        ("synced_peer_readded_tip", ""),
        ("Change Color", ""),
        ("Primary Color", ""),
        ("HSV Color", ""),
        ("Installation Successful!", ""),
        ("Installation failed!", ""),
        ("Reverse mouse wheel", ""),
        ("{} sessions", ""),
        ("scam_title", ""),
        ("scam_text1", ""),
        ("scam_text2", ""),
        ("Don't show again", ""),
        ("I Agree", ""),
        ("Decline", ""),
        ("Timeout in minutes", ""),
        ("auto_disconnect_option_tip", ""),
        ("Connection failed due to inactivity", ""),
        ("Check for software update on startup", ""),
        ("upgrade_rustdesk_server_pro_to_{}_tip", ""),
        ("pull_group_failed_tip", ""),
        ("Filter by intersection", ""),
        ("Remove wallpaper during incoming sessions", ""),
        ("Test", ""),
        ("display_is_plugged_out_msg", ""),
        ("No displays", ""),
        ("Open in new window", ""),
        ("Show displays as individual windows", ""),
        ("Use all my displays for the remote session", ""),
        ("selinux_tip", ""),
        ("Change view", ""),
        ("Big tiles", ""),
        ("Small tiles", ""),
        ("List", ""),
        ("Virtual display", ""),
        ("Plug out all", ""),
        ("True color (4:4:4)", ""),
        ("Enable blocking user input", ""),
        ("id_input_tip", ""),
        ("privacy_mode_impl_mag_tip", ""),
        ("privacy_mode_impl_virtual_display_tip", ""),
        ("Enter privacy mode", ""),
        ("Exit privacy mode", ""),
        ("idd_not_support_under_win10_2004_tip", ""),
        ("input_source_1_tip", ""),
        ("input_source_2_tip", ""),
        ("Swap control-command key", ""),
        ("swap-left-right-mouse", ""),
        ("2FA code", ""),
        ("More", ""),
        ("enable-2fa-title", ""),
        ("enable-2fa-desc", ""),
        ("wrong-2fa-code", ""),
        ("enter-2fa-title", ""),
        ("Email verification code must be 6 characters.", ""),
        ("2FA code must be 6 digits.", ""),
        ("Multiple Windows sessions found", ""),
        ("Please select the session you want to connect to", ""),
        ("powered_by_me", ""),
        ("outgoing_only_desk_tip", ""),
        ("preset_password_warning", ""),
        ("Security Alert", ""),
        ("My address book", ""),
        ("Personal", ""),
        ("Owner", ""),
        ("Set shared password", ""),
        ("Exist in", ""),
        ("Read-only", ""),
        ("Read/Write", ""),
        ("Full Control", ""),
        ("share_warning_tip", ""),
        ("Everyone", ""),
        ("ab_web_console_tip", ""),
        ("allow-only-conn-window-open-tip", ""),
        ("no_need_privacy_mode_no_physical_displays_tip", ""),
        ("Follow remote cursor", ""),
        ("Follow remote window focus", ""),
        ("default_proxy_tip", ""),
        ("no_audio_input_device_tip", ""),
        ("Incoming", ""),
        ("Outgoing", ""),
        ("Clear Wayland screen selection", ""),
        ("clear_Wayland_screen_selection_tip", ""),
        ("confirm_clear_Wayland_screen_selection_tip", ""),
        ("android_new_voice_call_tip", ""),
        ("texture_render_tip", ""),
        ("Use texture rendering", ""),
        ("Floating window", ""),
        ("floating_window_tip", ""),
        ("Keep screen on", ""),
        ("Never", ""),
        ("During controlled", ""),
        ("During service is on", ""),
        ("Capture screen using DirectX", ""),
        ("Back", ""),
        ("Apps", ""),
        ("Volume up", ""),
        ("Volume down", ""),
        ("Power", ""),
        ("Telegram bot", ""),
        ("enable-bot-tip", ""),
        ("enable-bot-desc", ""),
        ("cancel-2fa-confirm-tip", ""),
        ("cancel-bot-confirm-tip", ""),
        ("About RustDesk", ""),
        ("Send clipboard keystrokes", ""),
        ("network_error_tip", ""),
        ("Unlock with PIN", ""),
        ("Requires at least {} characters", ""),
        ("Wrong PIN", ""),
        ("Set PIN", ""),
        ("Enable trusted devices", ""),
        ("Manage trusted devices", ""),
        ("Platform", ""),
        ("Days remaining", ""),
        ("enable-trusted-devices-tip", ""),
        ("Parent directory", ""),
        ("Resume", ""),
        ("Invalid file name", ""),
        ("one-way-file-transfer-tip", ""),
        ("Authentication Required", ""),
        ("Authenticate", ""),
        ("web_id_input_tip", ""),
        ("Download", ""),
        ("Upload folder", ""),
        ("Upload files", ""),
        ("Clipboard is synchronized", ""),
        ("Update client clipboard", ""),
        ("Untagged", ""),
    ].iter().cloned().collect();
}