/// <binding BeforeBuild='build:emailTemplates' Clean='clean:emailTemplates' />
"use strict";

var gulp = require("gulp");
var concat = require("gulp-concat");
var cssmin = require("gulp-cssmin");
var uglify = require("gulp-uglify");
var config = require("gulp-ng-config");
var del = require("del");

/* Path definitions */
var paths = {};
paths.webroot = "./wwwroot/";
paths.templates = "./Templates/";
paths.emailTemplateSrc = paths.templates + "**/";
paths.emailTemplateDest = paths.webroot + "email/";
paths.emailTemplateClean = paths.webroot + "email/**/";

/* Clean */
gulp.task("clean:emailTemplates", function () {
    return del(paths.emailTemplateClean);
});

/* Build */
gulp.task("build:emailTemplates", function () {
    return gulp.src(paths.emailTemplateSrc)
        .pipe(gulp.dest(paths.emailTemplateDest));
});

/* Deploy */
gulp.task("deploy:emailTemplates", function () {
    return gulp.src(paths.emailTemplateSrc)
        .pipe(gulp.dest(paths.emailTemplateDest));
});
