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