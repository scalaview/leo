window.isMobile = function (mobile) {
    var reg = /^1\d{10}$/;
    return (mobile !== undefined && mobile !== '' && reg.test(mobile))
}

new Vue({
    el: '#records',
    delimiters: ['<%', '%>'],
    data: {
        items: [{phone: 1234, msg: "23445"}]
    },
    ready : function(){

    },
    methods: {
      loadRecords: function(){
        this.$http.get('/api/v1_users', function(v1users){
            this.$set('v1_user',v1users);
        });
      }
    }
})
new Vue({
    el: '#msg-btn',
    delimiters: ['<%', '%>'],
    data: {
        active: true,
        msg: "发 送",
        time: 0
    },
    methods: {
        send: function () {
          if(this.time > 0) return
          var phone = $("#phone").val()
          if(!isMobile(phone)){
            toastr.error("请输入正确的手机号码")
            return
          }
          var that = this
          this.active = !this.active
          if(this.active === false){
            this.time = 60
            setInterval(function(){
              that.countDown()
            }, 1000)
          }
          this.msg = this.active ? "发 送" : this.time
          this.souplus_send_code()
        },
        souplus_send_code: function(){
          var phone = $("#phone").val()
          if(isMobile(phone)){
            $.ajax({
              url: "/admin/souplus_send_code",
              method: "POST",
              dataType: "JSON",
              data: {
                phone: '11111111111'
              }
            }).success(function(data){
              if (data.err) {
                toastr.error(data.msg)
              }else{
                toastr.success(data.msg)
              }
            }).fail(function(err){
              console.log(err)
            })
          }else{
            toastr.error("请输入正确的手机号码")
          }
        },
        countDown: function(){
          if(this.time > 0){
            this.msg = this.time
            this.time = this.time - 1
          }else{
            clearInterval()
            this.msg = "发 送"
            this.$set('active', true)
          }
        }
    }
})