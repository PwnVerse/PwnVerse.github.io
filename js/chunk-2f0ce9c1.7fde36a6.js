(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-2f0ce9c1"],{"13b3":function(t,e,n){},"166a":function(t,e,n){},"604c":function(t,e,n){"use strict";n.d(e,"a",(function(){return u}));n("4de4"),n("7db0"),n("c740"),n("4160"),n("caad"),n("c975"),n("fb6a"),n("a434"),n("a9e3"),n("2532"),n("159b");var i=n("5530"),s=(n("166a"),n("a452")),r=n("7560"),a=n("58df"),o=n("d9bd"),u=Object(a["a"])(s["a"],r["a"]).extend({name:"base-item-group",props:{activeClass:{type:String,default:"v-item--active"},mandatory:Boolean,max:{type:[Number,String],default:null},multiple:Boolean},data:function(){return{internalLazyValue:void 0!==this.value?this.value:this.multiple?[]:void 0,items:[]}},computed:{classes:function(){return Object(i["a"])({"v-item-group":!0},this.themeClasses)},selectedIndex:function(){return this.selectedItem&&this.items.indexOf(this.selectedItem)||-1},selectedItem:function(){if(!this.multiple)return this.selectedItems[0]},selectedItems:function(){var t=this;return this.items.filter((function(e,n){return t.toggleMethod(t.getValue(e,n))}))},selectedValues:function(){return null==this.internalValue?[]:Array.isArray(this.internalValue)?this.internalValue:[this.internalValue]},toggleMethod:function(){var t=this;if(!this.multiple)return function(e){return t.internalValue===e};var e=this.internalValue;return Array.isArray(e)?function(t){return e.includes(t)}:function(){return!1}}},watch:{internalValue:"updateItemsState",items:"updateItemsState"},created:function(){this.multiple&&!Array.isArray(this.internalValue)&&Object(o["c"])("Model must be bound to an array if the multiple property is true.",this)},methods:{genData:function(){return{class:this.classes}},getValue:function(t,e){return null==t.value||""===t.value?e:t.value},onClick:function(t){this.updateInternalValue(this.getValue(t,this.items.indexOf(t)))},register:function(t){var e=this,n=this.items.push(t)-1;t.$on("change",(function(){return e.onClick(t)})),this.mandatory&&!this.selectedValues.length&&this.updateMandatory(),this.updateItem(t,n)},unregister:function(t){if(!this._isDestroyed){var e=this.items.indexOf(t),n=this.getValue(t,e);this.items.splice(e,1);var i=this.selectedValues.indexOf(n);if(!(i<0)){if(!this.mandatory)return this.updateInternalValue(n);this.multiple&&Array.isArray(this.internalValue)?this.internalValue=this.internalValue.filter((function(t){return t!==n})):this.internalValue=void 0,this.selectedItems.length||this.updateMandatory(!0)}}},updateItem:function(t,e){var n=this.getValue(t,e);t.isActive=this.toggleMethod(n)},updateItemsState:function(){var t=this;this.$nextTick((function(){if(t.mandatory&&!t.selectedItems.length)return t.updateMandatory();t.items.forEach(t.updateItem)}))},updateInternalValue:function(t){this.multiple?this.updateMultiple(t):this.updateSingle(t)},updateMandatory:function(t){if(this.items.length){var e=this.items.slice();t&&e.reverse();var n=e.find((function(t){return!t.disabled}));if(n){var i=this.items.indexOf(n);this.updateInternalValue(this.getValue(n,i))}}},updateMultiple:function(t){var e=Array.isArray(this.internalValue)?this.internalValue:[],n=e.slice(),i=n.findIndex((function(e){return e===t}));this.mandatory&&i>-1&&n.length-1<1||null!=this.max&&i<0&&n.length+1>this.max||(i>-1?n.splice(i,1):n.push(t),this.internalValue=n)},updateSingle:function(t){var e=t===this.internalValue;this.mandatory&&e||(this.internalValue=e?void 0:t)}},render:function(t){return t("div",this.genData(),this.$slots.default)}});u.extend({name:"v-item-group",provide:function(){return{itemGroup:this}}})},"63b7":function(t,e,n){},"9d26":function(t,e,n){"use strict";var i=n("132d");e["a"]=i["a"]},"9d65":function(t,e,n){"use strict";var i=n("d9bd"),s=n("2b0e");e["a"]=s["a"].extend().extend({name:"bootable",props:{eager:Boolean},data:function(){return{isBooted:!1}},computed:{hasContent:function(){return this.isBooted||this.eager||this.isActive}},watch:{isActive:function(){this.isBooted=!0}},created:function(){"lazy"in this.$attrs&&Object(i["d"])("lazy",this)},methods:{showLazyContent:function(t){return this.hasContent&&t?t():[this.$createElement()]}}})},afdd:function(t,e,n){"use strict";var i=n("8336");e["a"]=i["a"]},bb51:function(t,e,n){"use strict";n.r(e);var i=function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",[n("Header"),n("v-carousel",{staticClass:"pa-5",attrs:{cycle:"",continuous:"","hide-delimiter-background":"","hide-delimiters":"","show-arrows":!1}},[n("v-carousel-item",[n("v-sheet",{staticClass:"grey darken-3 mx-5 px-5",attrs:{height:"90%",tile:""}},[n("v-container",{attrs:{"fill-height":""}},[n("v-layout",{attrs:{"align-center":""}},[n("v-col",{attrs:{align:"center"}},[n("h1",{staticClass:"font-weight-thin",class:{"display-4 pb-3":t.$vuetify.breakpoint.smAndUp,"display-2 pb-1":t.$vuetify.breakpoint.xsOnly}},[t._v("Welcome")]),n("h3",{staticClass:"font-weight-thin headline"},[t._v("I write about different computer science topics.")])])],1)],1)],1)],1)],1),n("Footer")],1)},s=[],r=n("d4ec"),a=n("262e"),o=n("2caf"),u=n("9ab4"),c=n("60a3"),l=n("0418"),h=n("fd2d"),d=function(){var t=function(t){Object(a["a"])(n,t);var e=Object(o["a"])(n);function n(){return Object(r["a"])(this,n),e.apply(this,arguments)}return n}(c["c"]);return t=Object(u["a"])([Object(c["a"])({components:{Footer:h["a"],Header:l["a"]}})],t),t}(),f=d,v=f,m=n("2877"),p=n("6544"),g=n.n(p),b=(n("a9e3"),n("5530")),w=(n("63b7"),n("99af"),n("7db0"),n("c740"),n("13b3"),n("4160"),n("159b"),n("80d2")),y=function(t){var e=t.touchstartX,n=t.touchendX,i=t.touchstartY,s=t.touchendY,r=.5,a=16;t.offsetX=n-e,t.offsetY=s-i,Math.abs(t.offsetY)<r*Math.abs(t.offsetX)&&(t.left&&n<e-a&&t.left(t),t.right&&n>e+a&&t.right(t)),Math.abs(t.offsetX)<r*Math.abs(t.offsetY)&&(t.up&&s<i-a&&t.up(t),t.down&&s>i+a&&t.down(t))};function x(t,e){var n=t.changedTouches[0];e.touchstartX=n.clientX,e.touchstartY=n.clientY,e.start&&e.start(Object.assign(t,e))}function I(t,e){var n=t.changedTouches[0];e.touchendX=n.clientX,e.touchendY=n.clientY,e.end&&e.end(Object.assign(t,e)),y(e)}function O(t,e){var n=t.changedTouches[0];e.touchmoveX=n.clientX,e.touchmoveY=n.clientY,e.move&&e.move(Object.assign(t,e))}function T(t){var e={touchstartX:0,touchstartY:0,touchendX:0,touchendY:0,touchmoveX:0,touchmoveY:0,offsetX:0,offsetY:0,left:t.left,right:t.right,up:t.up,down:t.down,start:t.start,move:t.move,end:t.end};return{touchstart:function(t){return x(t,e)},touchend:function(t){return I(t,e)},touchmove:function(t){return O(t,e)}}}function V(t,e,n){var i=e.value,s=i.parent?t.parentElement:t,r=i.options||{passive:!0};if(s){var a=T(e.value);s._touchHandlers=Object(s._touchHandlers),s._touchHandlers[n.context._uid]=a,Object(w["t"])(a).forEach((function(t){s.addEventListener(t,a[t],r)}))}}function C(t,e,n){var i=e.value.parent?t.parentElement:t;if(i&&i._touchHandlers){var s=i._touchHandlers[n.context._uid];Object(w["t"])(s).forEach((function(t){i.removeEventListener(t,s[t])})),delete i._touchHandlers[n.context._uid]}}var j={inserted:V,unbind:C},$=j,B=n("afdd"),A=n("9d26"),S=n("604c"),_=S["a"].extend({name:"v-window",provide:function(){return{windowGroup:this}},directives:{Touch:$},props:{activeClass:{type:String,default:"v-window-item--active"},continuous:Boolean,mandatory:{type:Boolean,default:!0},nextIcon:{type:[Boolean,String],default:"$next"},prevIcon:{type:[Boolean,String],default:"$prev"},reverse:{type:Boolean,default:void 0},showArrows:Boolean,showArrowsOnHover:Boolean,touch:Object,touchless:Boolean,value:{required:!1},vertical:Boolean},data:function(){return{changedByDelimiters:!1,internalHeight:void 0,transitionHeight:void 0,transitionCount:0,isBooted:!1,isReverse:!1}},computed:{isActive:function(){return this.transitionCount>0},classes:function(){return Object(b["a"])(Object(b["a"])({},S["a"].options.computed.classes.call(this)),{},{"v-window--show-arrows-on-hover":this.showArrowsOnHover})},computedTransition:function(){if(!this.isBooted)return"";var t=this.vertical?"y":"x",e=this.$vuetify.rtl&&"x"===t?!this.internalReverse:this.internalReverse,n=e?"-reverse":"";return"v-window-".concat(t).concat(n,"-transition")},hasActiveItems:function(){return Boolean(this.items.find((function(t){return!t.disabled})))},hasNext:function(){return this.continuous||this.internalIndex<this.items.length-1},hasPrev:function(){return this.continuous||this.internalIndex>0},internalIndex:function(){var t=this;return this.items.findIndex((function(e,n){return t.internalValue===t.getValue(e,n)}))},internalReverse:function(){return this.reverse?!this.isReverse:this.isReverse}},watch:{internalIndex:"updateReverse"},mounted:function(){var t=this;window.requestAnimationFrame((function(){return t.isBooted=!0}))},methods:{genContainer:function(){var t=[this.$slots.default];return this.showArrows&&t.push(this.genControlIcons()),this.$createElement("div",{staticClass:"v-window__container",class:{"v-window__container--is-active":this.isActive},style:{height:this.internalHeight||this.transitionHeight}},t)},genIcon:function(t,e,n){var i=this;return this.$createElement("div",{staticClass:"v-window__".concat(t)},[this.$createElement(B["a"],{props:{icon:!0},attrs:{"aria-label":this.$vuetify.lang.t("$vuetify.carousel.".concat(t))},on:{click:function(){i.changedByDelimiters=!0,n()}}},[this.$createElement(A["a"],{props:{large:!0}},e)])])},genControlIcons:function(){var t=[],e=this.$vuetify.rtl?this.nextIcon:this.prevIcon;if(this.hasPrev&&e&&"string"===typeof e){var n=this.genIcon("prev",e,this.prev);n&&t.push(n)}var i=this.$vuetify.rtl?this.prevIcon:this.nextIcon;if(this.hasNext&&i&&"string"===typeof i){var s=this.genIcon("next",i,this.next);s&&t.push(s)}return t},getNextIndex:function(t){var e=(t+1)%this.items.length,n=this.items[e];return n.disabled?this.getNextIndex(e):e},getPrevIndex:function(t){var e=(t+this.items.length-1)%this.items.length,n=this.items[e];return n.disabled?this.getPrevIndex(e):e},next:function(){if(this.isReverse=this.$vuetify.rtl,this.hasActiveItems&&this.hasNext){var t=this.getNextIndex(this.internalIndex),e=this.items[t];this.internalValue=this.getValue(e,t)}},prev:function(){if(this.isReverse=!this.$vuetify.rtl,this.hasActiveItems&&this.hasPrev){var t=this.getPrevIndex(this.internalIndex),e=this.items[t];this.internalValue=this.getValue(e,t)}},updateReverse:function(t,e){this.changedByDelimiters?this.changedByDelimiters=!1:this.isReverse=t<e}},render:function(t){var e=this,n={staticClass:"v-window",class:this.classes,directives:[]};if(!this.touchless){var i=this.touch||{left:function(){e.$vuetify.rtl?e.prev():e.next()},right:function(){e.$vuetify.rtl?e.next():e.prev()},end:function(t){t.stopPropagation()},start:function(t){t.stopPropagation()}};n.directives.push({name:"touch",value:i})}return t("div",n,[this.genContainer()])}}),E=n("37c6"),D=S["a"].extend({name:"button-group",provide:function(){return{btnToggle:this}},computed:{classes:function(){return S["a"].options.computed.classes.call(this)}},methods:{genData:S["a"].options.methods.genData}}),H=n("d9bd"),k=_.extend({name:"v-carousel",props:{continuous:{type:Boolean,default:!0},cycle:Boolean,delimiterIcon:{type:String,default:"$delimiter"},height:{type:[Number,String],default:500},hideDelimiters:Boolean,hideDelimiterBackground:Boolean,interval:{type:[Number,String],default:6e3,validator:function(t){return t>0}},mandatory:{type:Boolean,default:!0},progress:Boolean,progressColor:String,showArrows:{type:Boolean,default:!0},verticalDelimiters:{type:String,default:void 0}},data:function(){return{internalHeight:this.height,slideTimeout:void 0}},computed:{classes:function(){return Object(b["a"])(Object(b["a"])({},_.options.computed.classes.call(this)),{},{"v-carousel":!0,"v-carousel--hide-delimiter-background":this.hideDelimiterBackground,"v-carousel--vertical-delimiters":this.isVertical})},isDark:function(){return this.dark||!this.light},isVertical:function(){return null!=this.verticalDelimiters}},watch:{internalValue:"restartTimeout",interval:"restartTimeout",height:function(t,e){t!==e&&t&&(this.internalHeight=t)},cycle:function(t){t?this.restartTimeout():(clearTimeout(this.slideTimeout),this.slideTimeout=void 0)}},created:function(){this.$attrs.hasOwnProperty("hide-controls")&&Object(H["a"])("hide-controls",':show-arrows="false"',this)},mounted:function(){this.startTimeout()},methods:{genControlIcons:function(){return this.isVertical?null:_.options.methods.genControlIcons.call(this)},genDelimiters:function(){return this.$createElement("div",{staticClass:"v-carousel__controls",style:{left:"left"===this.verticalDelimiters&&this.isVertical?0:"auto",right:"right"===this.verticalDelimiters?0:"auto"}},[this.genItems()])},genItems:function(){for(var t=this,e=this.items.length,n=[],i=0;i<e;i++){var s=this.$createElement(B["a"],{staticClass:"v-carousel__controls__item",attrs:{"aria-label":this.$vuetify.lang.t("$vuetify.carousel.ariaLabel.delimiter",i+1,e)},props:{icon:!0,small:!0,value:this.getValue(this.items[i],i)}},[this.$createElement(A["a"],{props:{size:18}},this.delimiterIcon)]);n.push(s)}return this.$createElement(D,{props:{value:this.internalValue,mandatory:this.mandatory},on:{change:function(e){t.internalValue=e}}},n)},genProgress:function(){return this.$createElement(E["a"],{staticClass:"v-carousel__progress",props:{color:this.progressColor,value:(this.internalIndex+1)/this.items.length*100}})},restartTimeout:function(){this.slideTimeout&&clearTimeout(this.slideTimeout),this.slideTimeout=void 0,window.requestAnimationFrame(this.startTimeout)},startTimeout:function(){this.cycle&&(this.slideTimeout=window.setTimeout(this.next,+this.interval>0?+this.interval:6e3))}},render:function(t){var e=_.options.render.call(this,t);return e.data.style="height: ".concat(Object(w["e"])(this.height),";"),this.hideDelimiters||e.children.push(this.genDelimiters()),(this.progress||this.progressColor)&&e.children.push(this.genProgress()),e}}),G=n("9d65"),M=n("4e82"),N=n("58df"),X=Object(N["a"])(G["a"],Object(M["a"])("windowGroup","v-window-item","v-window")),Y=X.extend().extend().extend({name:"v-window-item",directives:{Touch:$},props:{disabled:Boolean,reverseTransition:{type:[Boolean,String],default:void 0},transition:{type:[Boolean,String],default:void 0},value:{required:!1}},data:function(){return{isActive:!1,inTransition:!1}},computed:{classes:function(){return this.groupClasses},computedTransition:function(){return this.windowGroup.internalReverse?"undefined"!==typeof this.reverseTransition?this.reverseTransition||"":this.windowGroup.computedTransition:"undefined"!==typeof this.transition?this.transition||"":this.windowGroup.computedTransition}},methods:{genDefaultSlot:function(){return this.$slots.default},genWindowItem:function(){return this.$createElement("div",{staticClass:"v-window-item",class:this.classes,directives:[{name:"show",value:this.isActive}],on:this.$listeners},this.genDefaultSlot())},onAfterTransition:function(){this.inTransition&&(this.inTransition=!1,this.windowGroup.transitionCount>0&&(this.windowGroup.transitionCount--,0===this.windowGroup.transitionCount&&(this.windowGroup.transitionHeight=void 0)))},onBeforeTransition:function(){this.inTransition||(this.inTransition=!0,0===this.windowGroup.transitionCount&&(this.windowGroup.transitionHeight=Object(w["e"])(this.windowGroup.$el.clientHeight)),this.windowGroup.transitionCount++)},onTransitionCancelled:function(){this.onAfterTransition()},onEnter:function(t){var e=this;this.inTransition&&this.$nextTick((function(){e.computedTransition&&e.inTransition&&(e.windowGroup.transitionHeight=Object(w["e"])(t.clientHeight))}))}},render:function(t){var e=this;return t("transition",{props:{name:this.computedTransition},on:{beforeEnter:this.onBeforeTransition,afterEnter:this.onAfterTransition,enterCancelled:this.onTransitionCancelled,beforeLeave:this.onBeforeTransition,afterLeave:this.onAfterTransition,leaveCancelled:this.onTransitionCancelled,enter:this.onEnter}},this.showLazyContent((function(){return[e.genWindowItem()]})))}}),R=n("adda"),L=n("1c87"),P=Object(N["a"])(Y,L["a"]),z=P.extend({name:"v-carousel-item",inheritAttrs:!1,methods:{genDefaultSlot:function(){return[this.$createElement(R["a"],{staticClass:"v-carousel__item",props:Object(b["a"])(Object(b["a"])({},this.$attrs),{},{height:this.windowGroup.internalHeight}),on:this.$listeners,scopedSlots:{placeholder:this.$scopedSlots.placeholder}},Object(w["n"])(this))]},genWindowItem:function(){var t=this.generateRouteLink(),e=t.tag,n=t.data;return n.staticClass="v-window-item",n.directives.push({name:"show",value:this.isActive}),this.$createElement(e,n,this.genDefaultSlot())}}}),W=(n("caad"),n("13d5"),n("45fc"),n("4ec9"),n("b64b"),n("d3b7"),n("ac1f"),n("3ca3"),n("5319"),n("2ca0"),n("ddb0"),n("ade3")),q=(n("4b85"),n("2b0e")),F=n("d9f7"),J=["sm","md","lg","xl"],U=function(){return J.reduce((function(t,e){return t[e]={type:[Boolean,String,Number],default:!1},t}),{})}(),K=function(){return J.reduce((function(t,e){return t["offset"+Object(w["z"])(e)]={type:[String,Number],default:null},t}),{})}(),Q=function(){return J.reduce((function(t,e){return t["order"+Object(w["z"])(e)]={type:[String,Number],default:null},t}),{})}(),Z={col:Object.keys(U),offset:Object.keys(K),order:Object.keys(Q)};function tt(t,e,n){var i=t;if(null!=n&&!1!==n){if(e){var s=e.replace(t,"");i+="-".concat(s)}return"col"!==t||""!==n&&!0!==n?(i+="-".concat(n),i.toLowerCase()):i.toLowerCase()}}var et=new Map,nt=q["a"].extend({name:"v-col",functional:!0,props:Object(b["a"])(Object(b["a"])(Object(b["a"])(Object(b["a"])({cols:{type:[Boolean,String,Number],default:!1}},U),{},{offset:{type:[String,Number],default:null}},K),{},{order:{type:[String,Number],default:null}},Q),{},{alignSelf:{type:String,default:null,validator:function(t){return["auto","start","end","center","baseline","stretch"].includes(t)}},tag:{type:String,default:"div"}}),render:function(t,e){var n=e.props,i=e.data,s=e.children,r=(e.parent,"");for(var a in n)r+=String(n[a]);var o=et.get(r);return o||function(){var t,e;for(e in o=[],Z)Z[e].forEach((function(t){var i=n[t],s=tt(e,t,i);s&&o.push(s)}));var i=o.some((function(t){return t.startsWith("col-")}));o.push((t={col:!i||!n.cols},Object(W["a"])(t,"col-".concat(n.cols),n.cols),Object(W["a"])(t,"offset-".concat(n.offset),n.offset),Object(W["a"])(t,"order-".concat(n.order),n.order),Object(W["a"])(t,"align-self-".concat(n.alignSelf),n.alignSelf),t)),et.set(r,o)}(),t(n.tag,Object(F["a"])(i,{class:o}),s)}}),it=n("a523"),st=n("a722"),rt=n("8dd9"),at=Object(m["a"])(v,i,s,!1,null,null,null);e["default"]=at.exports;g()(at,{VCarousel:k,VCarouselItem:z,VCol:nt,VContainer:it["a"],VLayout:st["a"],VSheet:rt["a"]})},c740:function(t,e,n){"use strict";var i=n("23e7"),s=n("b727").findIndex,r=n("44d2"),a=n("ae40"),o="findIndex",u=!0,c=a(o);o in[]&&Array(1)[o]((function(){u=!1})),i({target:"Array",proto:!0,forced:u||!c},{findIndex:function(t){return s(this,t,arguments.length>1?arguments[1]:void 0)}}),r(o)}}]);
//# sourceMappingURL=chunk-2f0ce9c1.7fde36a6.js.map